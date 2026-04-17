# Building and installing

## Prerequisites

- Python 3.11 or later
- [pip](https://pip.pypa.io/en/stable/installation/)

## Install hatch

[Hatch](https://hatch.pypa.io) is the build and environment manager for this package.

```bash
pip install hatch
```

## Install from source

The simplest way to use the library is to install it directly:

```bash
pip install .
```

To run `samples/sso_then_agent.py`, also install the Nova Act SDK:

```bash
pip install ".[nova-act]"
```

For the full development environment (Nova Act SDK + dev tools):

```bash
pip install ".[nova-act,dev]"
```

Install the Playwright browser required for the browser-based callback strategies:

```bash
playwright install chromium
```

## Build distributable artifacts

To produce a wheel and source distribution:

```bash
hatch build
```

Artifacts are written to `build/`. The wheel can be installed with:

```bash
pip install build/*.whl
```

## Lint and type-check

```bash
hatch run lint      # ruff
hatch run typing    # mypy
hatch run format    # ruff format + autofix
```