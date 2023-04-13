#!/bin/bash
set -e

if [ "$1" = 'build' ]; then
    ./build.sh "$2"
else
    exec "$@"
fi
