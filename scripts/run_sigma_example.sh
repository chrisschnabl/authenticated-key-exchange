#!/bin/bash
set -e;

cd "$(dirname "$0")/.."

docker build -f scripts/Dockerfile.base -t base .

docker build -f scripts/Dockerfile.sigma -t sigma .

docker run --rm sigma
