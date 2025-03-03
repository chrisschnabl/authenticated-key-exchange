# P079 Lab 02

Make sure to have commit-hooks installed for typing, linting, tests

```
pre-commit install
```

# Run

## Typing

```bash
uv run mypy
```

## Locally

Requires `uv` to be installed.

```bash
uv run src/example.py
```

## Dockerized

```bash
./scripts/run.sh
```

# Run tests

## Locally

Requires `uv` to be installed.

```bash
uv run pytest
```

## Dockerized

```bash
./scripts/run_tests.sh
```
