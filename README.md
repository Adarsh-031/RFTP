# RUDP Secure File Transfer (ShareIt)

UDP-based reliable file transfer with application-layer security (RSA + AES-GCM).

## Status
- Scaffold created

## Layout
- `src/`: core implementation
- `docs/`: documentation and reports
- `tests/`: tests

## Package Management (uv)
Set up the environment and install dependencies with `uv`:

```bash
uv venv
uv pip install -e .
```

## Next Steps
- Implement UDP client/server skeletons
- Define packet header format
- Add crypto handshake
