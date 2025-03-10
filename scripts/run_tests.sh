#!/bin/bash
set -e;

cd "$(dirname "$0")/.."

docker build -f scripts/Dockerfile.base -t base .

docker build -f scripts/Dockerfile.test -t test .

docker run --rm test
