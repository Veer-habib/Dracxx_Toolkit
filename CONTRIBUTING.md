# Contributing to DRACXX

Thanks for your interest in improving DRACXX.

## Ground rules

1. **No exploitation code.** PRs adding exploit execution, brute force,
   payload delivery, or any offensive capability will be rejected
   outright, regardless of stated intent.
2. Keep tool adapters read-only/detection-only and gracefully degrade
   when a binary is missing.
3. New CVE/CPE logic must use real version-range evaluation — never
   treat a product-name match as proof of a vulnerability.
4. Add tests for new engines (recon, CVE, risk, confidence, reporting).

## Dev setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest pytest-asyncio
pytest -v
```

## Style

- Python 3.11+, type hints where practical.
- Run `make lint` (py_compile) before submitting.
