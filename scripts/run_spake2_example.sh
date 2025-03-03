#!/bin/bash
set -e;

cd "$(dirname "$0")/.."

docker build -f scripts/Dockerfile.base -t base .

docker build -f scripts/Dockerfile.spake2 -t spake2 .

docker run --rm spake2
