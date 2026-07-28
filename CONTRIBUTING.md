# Contributing

This project follows HyperDbg's contribution conventions so it stays familiar to the
maintainers.

- **License:** all contributions are GPL-3.0-or-later. Every source file carries the
  Doxygen-style GPLv3 header used across HyperDbg.
- **Discuss first:** open an issue/discussion before starting substantial work.
- **Target branch:** pull requests target the **`Dev`** branch (never `main`/`master`),
  matching the HyperDbg repositories.
- **Style:** `ruff` for lint/format (`ruff check .` and `ruff format .`); `snake_case`
  for functions/variables, `CamelCase` for classes.
- **Tests:** `pytest`. Logic is tested against a mocked FFI layer so the suite runs without
  a HyperDbg host; FFI signatures are kept in one place (`ffi.py`) and verified against
  `HyperDbgLibImports.h`.

## Local setup

```bash
pip install -e ".[dev]"
pytest
ruff check .
```
