# Development on Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip unzip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest
```

Keep tests deterministic and offline. Every new check needs tests for expected behavior, malformed input, errors and safe stopping.
