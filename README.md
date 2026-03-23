# RFTP (Reliable UDP File Transfer)

RFTP is a UDP-based file transfer project with:

- reliability on top of UDP (chunking + ACK/retry + resume)
- application-layer encryption (RSA session key exchange + AES-GCM per chunk)
- desktop GUI built with `customtkinter`

## Features

- Run as a central server or as a client from the GUI.
- Upload files to server storage.
- Browse and download files from server storage.
- Pause/resume controls in client transfer UI.
- Server-side file catalog endpoint.

## Project Layout

- `main.py`: GUI entrypoint.
- `src/gui.py`: desktop UI.
- `src/udp_server.py`: threaded UDP server.
- `src/udp_client.py`: client transfer logic.
- `src/protocol.py`: packet formats and serialization.
- `src/security.py`: RSA/AES-GCM helpers.
- `tests/test_rudp.py`: unit tests.

## Prerequisites

- Linux/macOS/Windows
- Python `3.12+`
- `uv` (recommended make sure you install uv beforehand) or `pip`(uv is a python package manager. faster than pip!!!)
- Tk support for Python (`tkinter`) installed on your system

On Ubuntu/Debian, if `tkinter` is missing:

```bash
sudo apt-get update
sudo apt-get install -y python3-tk
```

## Setup (Recommended: uv)

From project root:

```bash
uv venv
source .venv/bin/activate
uv pip install -e .
```

## Setup (Alternative: pip)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Run the App (GUI)

From project root:

```bash
uv run main.py
```

If you are already in an activated virtual environment:

```bash
python main.py
```

### Typical Local Test Flow (Two App Instances)

1. Open terminal A and run `uv run main.py`.
2. In that window choose `Continue As Server`, then start server on `0.0.0.0:9000`.
3. Open terminal B and run `uv run main.py`.
4. In that window choose `Continue As Client`.
5. Upload: choose server IP (for same machine use `127.0.0.1`) and port `9000`, then start upload.
6. Download: refresh server files, select file, choose destination, and start download.

## CLI Usage

### Start Server

```bash
uv run -m src.udp_server --host 0.0.0.0 --port 9000 --output-dir server_storage
```

### Upload File

```bash
uv run -m src.udp_client --host 127.0.0.1 --port 9000 --upload-file /absolute/path/to/file.bin
```

### Download File

```bash
uv run -m src.udp_client --host 127.0.0.1 --port 9000 --download-file file.bin --save-path ./downloads/file.bin
```

## Run Tests

The project test suite is `unittest`-based:

```bash
python -m unittest -q
```

If you prefer `uv`:

```bash
uv run python -m unittest -q
```

## Troubleshooting

- `ModuleNotFoundError: tkinter`: install system Tk package (example above).
- `Address already in use`: pick a different `--port` or stop previous server.
- GUI opens but no transfer: verify client is pointing to the correct server IP and same port.
- Firewall issues: allow UDP traffic on the selected port.

## Notes

This project uses custom secure transport logic at the application layer and is not a drop-in replacement for TLS/DTLS.
