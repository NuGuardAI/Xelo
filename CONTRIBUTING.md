# Contributing

## Development
```bash
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src
```

## Pull Requests
- Add tests for behavior changes.
- Keep API changes backward compatible unless versioned major.
- Do not add hardcoded credentials or secrets.

## Security
Report vulnerabilities via `SECURITY.md`.
