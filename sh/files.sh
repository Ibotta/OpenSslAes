#!/bin/sh
set -x

if [ $1 = 'enc' ]; then
    openssl enc -aes-128-cbc -pass "$4" -in "$2" -out "$3"
elif [ $1 = 'dec' ]; then
    openssl enc -d -aes-128-cbc -pass "$4" -in "$2" -out "$3"
fi
