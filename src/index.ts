import express from "express";
import passport from "passport";
import session from "express-session";
import Redis from "ioredis";
import connectRedis from "connect-redis";
import { Strategy as LocalStrategy } from "passport-local";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { existsSync } from "fs";
import { resolve } from "path";
import cors from "cors";
import bodyParser from "body-parser";
import { promisify } from "util";

const { HASH_SALT_ROUNDS } = process.env;

const hash = promisify(bcrypt.hash);
const hashPassword = (password) => {
  return hash(password, parseInt(HASH_SALT_ROUNDS || "20000"));
};

let dotenvPath = resolve(process.cwd(), ".env.local");
if (!existsSync(dotenvPath)) dotenvPath = resolve(process.cwd(), ".env");

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config({ path: dotenvPath });
}

const RedisStore = connectRedis(session);

const redis = new Redis(process.env.REDIS_URL);
const USER_KEY_PREFIX = "user";
const USER_ID_BY_EMAIL_KEY_PREFIX = "userIdByEmail";
const USER_ID_BY_PUBLIC_KEY = "userIdByPublicKey";
const SECRETS_BY_USER_IDS_KEY = "secretsByUserIds";
const key = (...keyParts: string[]) => keyParts.join(":");
const getJSON = async (aKey: string) => {
  const result = await redis.get(aKey);
  if (!result) return result;
  return JSON.parse(result);
};
const setJSON = async (aKey: string, value: any) => {
  await redis.set(aKey, JSON.stringify(value));
  return value;
};

type User = {
  id: string;
  email: string;
  password: string;
  approved?: boolean;
};

//Create a passport middleware to handle User login
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (
      email: string,
      password: string,
      done: (err: any, result: any) => void
    ) => {
      const userId = await getJSON(key(USER_ID_BY_EMAIL_KEY_PREFIX, email));
      const user: User = await getJSON(key(USER_KEY_PREFIX, userId));
      if (!user || !user.approved) return done(null, false);
      bcrypt.compare(
        password,
        user.password,
        (err: string | undefined, isValid: boolean) => {
          if (err) {
            return done(err, null);
          }
          if (!isValid) {
            return done(null, false);
          }
          return done(null, user);
        }
      );
    }
  )
);

passport.serializeUser(function (user: User, done) {
  done(null, user.id);
});
passport.deserializeUser(async function (id: string, done) {
  const user: User = await getJSON(key(USER_KEY_PREFIX, id));
  done(null, user);
});

const { LOCAL, REDIS_STORE_SECRET, CORS_URL } = process.env;

const local = LOCAL === "true";
const app = local ? require("https-localhost")() : express();
if (!local) {
  console.log("running app locally with fake https");
}

app.use(
  cors({
    credentials: true,
    origin: CORS_URL,
  })
);

app.use(bodyParser.json());
if (!REDIS_STORE_SECRET)
  throw new Error("a REDIS_STORE_SECRET environment variable must be set");
app.use(
  session({
    store: new RedisStore({
      client: redis,
    }),
    secret: REDIS_STORE_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: true,
      httpOnly: true,
      sameSite: "none",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

//When the user sends a post request to this route, passport authenticates the user based on the
//middleware created previously
// FIXME: protect against someone who tries to register too many times (CAPTCHA?)
app.post("/signup", async (req, res, next) => {
  const { email, name, password } = req.body;
  const userId = await getJSON(key(USER_ID_BY_EMAIL_KEY_PREFIX, email));
  if (userId) {
    throw new Error("user exists with that email");
  }
  const user = await setJSON(userId, {
    name,
    email,
    password: await hashPassword(password),
  });
  res.json({
    message: "Signup successful",
    user,
  });
});

app.post("/login", async (req, res, next) => {
  passport.authenticate("local", async (err, user, info) => {
    try {
      if (err || !user) {
        const error = new Error("An Error occurred");
        return next(error);
      }
      req.login(user, {}, async (error) => {
        if (error) return next(error);

        //It worked
        return res.end("ok");
      });
    } catch (error) {
      return next(error);
    }
  })(req, res, next);
});

app.post("/registerPublicKey", async (req, res, next) => {
  // FIXME: protect against someone who tries to claim too many identities
  try {
    const user: User = req.user as User;
    if (!user) {
      const error = new Error("An Error occurred");
      return next(error);
    }
    const publicKey = req.body.publicKey;

    const success = await redis.setnx(
      key(USER_ID_BY_PUBLIC_KEY, publicKey),
      user.id
    );
    if (!success) {
      const error = new Error("An Error occurred");
      return next(error);
    }

    //We don't want to store the sensitive information such as the
    //user password in the token so we pick only the email and id
    const body = {
      id: user.id,
      email: user.email,
      publicKey,
    };

    //Sign the JWT token and populate the payload with the user email and id
    const token = jwt.sign({ user: body }, process.env.JWT_PRIVATE_KEY, {
      algorithm: "RS256",
      expiresIn: "365d", //A long expiry combined with frequent key updates should maintain security and availability
    });

    const serverPublicKey = process.env.JWT_PUBLIC_KEY;

    //Send back the token to the user
    return res.json({ token, serverPublicKey });
  } catch (error) {
    return next(error);
  }
});

// Debug keypair
// app.get("/checkKeypair", (req, res, next) => {
//   const privateKey = process.env.JWT_PRIVATE_KEY;
//   const testToken = jwt.sign(
//     { foo: "bar" },
//     privateKey,

//     {
//       algorithm: "RS256"
//     }
//   );

//   const serverPublicKey = process.env.JWT_PUBLIC_KEY;

//   res.json(
//     jwt.verify(testToken, serverPublicKey, {
//       algorithms: ["RS256"]
//     })
//   );
// });

app.post("/sharedSecret", async (req, res, next) => {
  // FIXME: protect against someone who tries to register too many secrets
  try {
    const user: User = req.user as User;
    if (!user) {
      const error = new Error("An Error occurred");
      return next(error);
    }
    const { secret, keyId, userIds: userIdsRaw } = req.body;
    const userIds = [
      ...userIdsRaw.filter((uid) => uid !== user.id),
      user.id,
    ].sort();
    userIds.push(keyId);
    const userIdString = userIds.join(",");
    const newKey = key(SECRETS_BY_USER_IDS_KEY, userIdString);
    const success = await redis.setnx(newKey, secret);
    if (!success) {
      return res.json({ secret: await redis.get(newKey), key: userIdString });
    } else {
      return res.json({ secret, key: userIdString });
    }
  } catch (error) {
    return next(error);
  }
});

app.post("/logout", async (req, res, next) => {
  if (!req.session) return res.end("not logged in");
  req.logout();
  req.session.destroy(function () {
    res.end("logged out");
  });
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`🚀 Server ready on port ${port}!`));
