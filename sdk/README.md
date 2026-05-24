# Vault-Zero Python SDK

## Install
```bash
pip install vault-zero-sdk
```

## Setup
Add to your .env file:
```env
VZK_KEY=vzk_your_key_here
```

## Usage
```python
from vaultzero import get

MY_KEY = get("MY_KEY")           # raises if not found
MY_KEY = get("MY_KEY", "")       # returns "" if not found
```

## Requirements
Vault-Zero desktop app must be running and unlocked.
