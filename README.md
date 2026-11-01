# Authorized Port Scanner

TCP connect scanner (Python 3.8+, no dependencies) that only scans targets
listed in `authorized_targets.txt` and requires an explicit confirmation flag.

## Run (Windows / VS Code terminal)

```
python scanner.py 127.0.0.1 -p 1-1024 --i-am-authorized --banner --html report.html --json report.json --db scans.db
python scanner.py 127.0.0.1 --i-am-authorized
```

## Test

```
pip install pytest
pytest -v
```

## Safety controls

- Scope allowlist: any target outside it is blocked, and the block is logged.
- `--i-am-authorized` flag required every run.
- Max 256 hosts per scan, max 200 threads.
- `audit.log` records every start, end and blocked attempt.
- Plain TCP connect only: no stealth or evasion techniques.

## Mapping to the project brief

| Brief item | Where |
|---|---|
| Backend / security tool | `scanner.py` |
| Database integration | SQLite via `--db` |
| Reporting | JSON + HTML via `--json` / `--html` |
| Automated testing | `test_scanner.py` |
| Frontend / API (optional next step) | wrap `run_scan` in Flask/FastAPI, add a form + results table |
