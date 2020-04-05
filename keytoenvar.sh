#!/usr/bin/env bash
file=$1
awk 'BEGIN{}{out=out$0"\\n"}END{print out}' $file| sed 's/\n$//'
