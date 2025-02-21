#!/bin/bash
set -e;

cd "$(dirname "$0")/.."

# Build the base docker
docker build -f scripts/Dockerfile.base -t base .

# Build the test docker
docker build -f scripts/Dockerfile.test -t test .

# Run the container
docker run --rm test
