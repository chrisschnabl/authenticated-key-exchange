#!/bin/bash
set -e;

cd "$(dirname "$0")/.."

# Build the base docker
docker build -f scripts/Dockerfile.base -t base .

# Build the example docker
docker build -f scripts/Dockerfile.example -t example .

# Run the container
docker run --rm example
