import argparse
import queue
import secrets
import socket
import threading
from pathlib import Path
from typing import Callable

from src.protocol import (
    CHUNK_SIZE,
    HELLO_STATUS_NOT_FOUND,
    HELLO_STATUS_OK,
    PACKET_TYPE_ACK,
    PACKET_TYPE_DATA,
    PACKET_TYPE_HELLO,
    PACKET_TYPE_KEY,
    PACKET_TYPE_LIST_FILES,
    SESSION_MODE_DOWNLOAD,
    SESSION_MODE_UPLOAD,
    build_ack_packet,
    build_data_packet,
    build_hello_ack_packet,
    build_key_ack_packet,
    build_list_response_packet,
    chunk_file,
    parse_list_files_packet,
    parse_ack_packet,
    parse_data_packet,
    parse_header,
    parse_hello_packet,
    parse_key_packet,
)
from src.security import (
    decrypt_chunk,
    decrypt_session_key,
    encrypt_chunk,
    export_public_key,
    generate_server_rsa_key,
)


ServerEventCallback = Callable[[dict[str, object]], None]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RUDP Secure File Transfer Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=9000, help="Bind port")
    parser.add_argument(
        "--output-dir",
        default="server_storage",
        help="Directory for files stored on the central server",
    )
    return parser.parse_args()


class BaseSession(threading.Thread):
    def __init__(
        self,
        session_id: int,
        server_socket: socket.socket,
        server_key,
        storage_dir: Path,
        filename: str,
        mode: int,
        event_callback: ServerEventCallback | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.session_id = session_id
        self.server_socket = server_socket
        self.server_key = server_key
        self.storage_dir = storage_dir
        self.filename = Path(filename).name
        self.mode = mode
        self.public_key = export_public_key(server_key)
        self.session_key: bytes | None = None
        self.client_addr: tuple[str, int] | None = None
        self.queue: queue.Queue[tuple[bytes, tuple[str, int]] | None] = queue.Queue()
        self.event_callback = event_callback
        self.stopped = False

    def emit_event(self, event: dict[str, object]) -> None:
        if self.event_callback is not None:
            self.event_callback(event)

    def enqueue(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self.stopped:
            return
        self.queue.put((packet, addr))

    def stop(self) -> None:
        self.stopped = True
        self.queue.put(None)

    def run(self) -> None:
        while True:
            item = self.queue.get()
            if item is None:
                return
            packet, addr = item
            if self.stopped:
                return
            try:
                self.handle_packet(packet, addr)
            except Exception as exc:
                self.emit_event(
                    {
                        "type": "error",
                        "session_id": self.session_id,
                        "filename": self.filename,
                        "status": str(exc),
                    }
                )

    def handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        raise NotImplementedError

    @property
    def path(self) -> Path:
        return self.storage_dir / self.filename


class UploadSession(BaseSession):
    def __init__(
        self,
        session_id: int,
        server_socket: socket.socket,
        server_key,
        storage_dir: Path,
        filename: str,
        total_chunks: int,
        event_callback: ServerEventCallback | None = None,
    ) -> None:
        super().__init__(
            session_id,
            server_socket,
            server_key,
            storage_dir,
            filename,
            SESSION_MODE_UPLOAD,
            event_callback=event_callback,
        )
        self.total_chunks = total_chunks
        self.temp_path = storage_dir / f".{self.filename}.{session_id}.part"
        self.received_sequences: set[int] = set()
        self.temp_path.parent.mkdir(parents=True, exist_ok=True)
        self.temp_file = self.temp_path.open("w+b")

    def finalize(self) -> None:
        self.temp_file.close()
        self.temp_path.replace(self.path)

    def close(self) -> None:
        self.temp_file.close()
        if self.temp_path.exists():
            self.temp_path.unlink()

    def handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self.stopped:
            return
        packet_type, _, _ = parse_header(packet)
        self.client_addr = addr

        if packet_type == PACKET_TYPE_HELLO:
            self.handle_hello(packet, addr)
            return
        if packet_type == PACKET_TYPE_KEY:
            self.handle_key(packet, addr)
            return
        if packet_type == PACKET_TYPE_DATA:
            self.handle_data(packet, addr)
            return
        raise ValueError("unsupported upload packet type")

    def handle_hello(self, packet: bytes, addr: tuple[str, int]) -> None:
        session_id, mode, total_chunks, filename, _ = parse_hello_packet(packet)
        if mode != SESSION_MODE_UPLOAD:
            raise ValueError("session mode mismatch")
        if session_id not in (0, self.session_id):
            raise ValueError("session id mismatch")
        if total_chunks != self.total_chunks or Path(filename).name != self.filename:
            raise ValueError("upload metadata mismatch")
        self.server_socket.sendto(
            build_hello_ack_packet(self.session_id, HELLO_STATUS_OK, self.total_chunks, self.public_key),
            addr,
        )

    def handle_key(self, packet: bytes, addr: tuple[str, int]) -> None:
        session_id, encrypted_key = parse_key_packet(packet)
        if session_id != self.session_id:
            raise ValueError("session id mismatch")
        self.session_key = decrypt_session_key(self.server_key, encrypted_key)
        self.server_socket.sendto(build_key_ack_packet(self.session_id), addr)

    def handle_data(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self.session_key is None:
            raise ValueError("received data before session key exchange")

        session_id, sequence, total_chunks, is_last, nonce, ciphertext, tag = parse_data_packet(packet)
        if session_id != self.session_id or total_chunks != self.total_chunks:
            raise ValueError("upload data metadata mismatch")

        payload = decrypt_chunk(
            self.session_key,
            self.session_id,
            sequence,
            total_chunks,
            is_last,
            nonce,
            ciphertext,
            tag,
        )
        if sequence not in self.received_sequences:
            self.temp_file.seek(sequence * CHUNK_SIZE)
            self.temp_file.write(payload)
            self.temp_file.flush()
            self.received_sequences.add(sequence)
        self.server_socket.sendto(build_ack_packet(self.session_id, sequence), addr)
        self.emit_event(
            {
                "type": "progress",
                "session_id": self.session_id,
                "filename": self.filename,
                "mode": "upload",
                "received": len(self.received_sequences),
                "total": self.total_chunks,
                "status": f"Uploading {self.filename}",
                "path": str(self.path),
            }
        )
        if len(self.received_sequences) == self.total_chunks:
            self.finalize()
            self.emit_event(
                {
                    "type": "complete",
                    "session_id": self.session_id,
                    "filename": self.filename,
                    "mode": "upload",
                    "received": self.total_chunks,
                    "total": self.total_chunks,
                    "status": f"Stored {self.filename}",
                    "path": str(self.path),
                }
            )


class DownloadSession(BaseSession):
    def __init__(
        self,
        session_id: int,
        server_socket: socket.socket,
        server_key,
        storage_dir: Path,
        filename: str,
        event_callback: ServerEventCallback | None = None,
    ) -> None:
        super().__init__(
            session_id,
            server_socket,
            server_key,
            storage_dir,
            filename,
            SESSION_MODE_DOWNLOAD,
            event_callback=event_callback,
        )
        self.chunks = chunk_file(self.path)
        self.total_chunks = len(self.chunks)
        self.pending_sequences = {sequence for sequence, _, _ in self.chunks}
        self.acked_sequences: set[int] = set()
        self.ack_queue: queue.Queue[int] = queue.Queue()
        self.sender_thread: threading.Thread | None = None

    def handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        if self.stopped:
            return
        packet_type, _, _ = parse_header(packet)
        self.client_addr = addr

        if packet_type == PACKET_TYPE_HELLO:
            self.handle_hello(packet, addr)
            return
        if packet_type == PACKET_TYPE_KEY:
            self.handle_key(packet, addr)
            return
        if packet_type == PACKET_TYPE_ACK:
            self.handle_ack(packet)
            return
        raise ValueError("unsupported download packet type")

    def handle_hello(self, packet: bytes, addr: tuple[str, int]) -> None:
        session_id, mode, total_chunks, filename, missing_sequences = parse_hello_packet(packet)
        if mode != SESSION_MODE_DOWNLOAD:
            raise ValueError("session mode mismatch")
        if session_id not in (0, self.session_id):
            raise ValueError("session id mismatch")
        if Path(filename).name != self.filename:
            raise ValueError("download filename mismatch")
        if total_chunks not in (0, self.total_chunks):
            raise ValueError("download total chunk mismatch")
        self.pending_sequences = missing_sequences or set(range(self.total_chunks))
        self.server_socket.sendto(
            build_hello_ack_packet(self.session_id, HELLO_STATUS_OK, self.total_chunks, self.public_key),
            addr,
        )

    def handle_key(self, packet: bytes, addr: tuple[str, int]) -> None:
        session_id, encrypted_key = parse_key_packet(packet)
        if session_id != self.session_id:
            raise ValueError("session id mismatch")
        self.session_key = decrypt_session_key(self.server_key, encrypted_key)
        self.server_socket.sendto(build_key_ack_packet(self.session_id), addr)
        if self.sender_thread is None or not self.sender_thread.is_alive():
            self.sender_thread = threading.Thread(target=self.send_chunks, daemon=True)
            self.sender_thread.start()

    def handle_ack(self, packet: bytes) -> None:
        session_id, sequence = parse_ack_packet(packet)
        if session_id != self.session_id:
            raise ValueError("session id mismatch")
        self.ack_queue.put(sequence)

    def send_chunks(self) -> None:
        if self.stopped or self.client_addr is None or self.session_key is None:
            return

        for sequence, payload, is_last in self.chunks:
            if self.stopped:
                return
            if sequence not in self.pending_sequences:
                continue

            nonce, ciphertext, tag = encrypt_chunk(
                self.session_key,
                self.session_id,
                sequence,
                self.total_chunks,
                is_last,
                payload,
            )
            packet = build_data_packet(
                self.session_id,
                sequence,
                self.total_chunks,
                is_last,
                nonce,
                ciphertext,
                tag,
            )

            for _ in range(5):
                if self.stopped:
                    return
                try:
                    self.server_socket.sendto(packet, self.client_addr)
                except OSError:
                    return
                try:
                    ack_sequence = self.ack_queue.get(timeout=1.0)
                except queue.Empty:
                    if self.stopped:
                        return
                    continue
                if ack_sequence == sequence:
                    self.acked_sequences.add(sequence)
                    self.pending_sequences.discard(sequence)
                    self.emit_event(
                        {
                            "type": "progress",
                            "session_id": self.session_id,
                            "filename": self.filename,
                            "mode": "download",
                            "received": len(self.acked_sequences),
                            "total": self.total_chunks,
                            "status": f"Serving {self.filename}",
                            "path": str(self.path),
                        }
                    )
                    break
            else:
                # Stop on the first stalled chunk and wait for the client to reconnect
                # with its missing-sequence bitmap instead of flooding the socket.
                return

        if len(self.acked_sequences) == self.total_chunks:
            self.emit_event(
                {
                    "type": "complete",
                    "session_id": self.session_id,
                    "filename": self.filename,
                    "mode": "download",
                    "received": self.total_chunks,
                    "total": self.total_chunks,
                    "status": f"Delivered {self.filename}",
                    "path": str(self.path),
                }
            )


class ThreadedRUDPServer:
    def __init__(
        self,
        host: str,
        port: int,
        output_dir: str | None,
        event_callback: ServerEventCallback | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.storage_dir = Path(output_dir or "server_storage")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((host, port))
        self.server_key = generate_server_rsa_key()
        self.sessions: dict[int, BaseSession] = {}
        self.lock = threading.Lock()
        self.event_callback = event_callback
        self.running = True

    def allocate_session_id(self) -> int:
        while True:
            session_id = secrets.randbits(32)
            if session_id != 0 and session_id not in self.sessions:
                return session_id

    def get_or_create_session(self, packet: bytes) -> BaseSession:
        packet_type, session_id, _ = parse_header(packet)
        if packet_type != PACKET_TYPE_HELLO:
            with self.lock:
                if session_id not in self.sessions:
                    raise ValueError(f"unknown session {session_id}")
                return self.sessions[session_id]

        _, mode, total_chunks, filename, _ = parse_hello_packet(packet)
        with self.lock:
            if session_id != 0 and session_id in self.sessions:
                return self.sessions[session_id]

            new_session_id = session_id or self.allocate_session_id()
            if mode == SESSION_MODE_UPLOAD:
                session: BaseSession = UploadSession(
                    new_session_id,
                    self.server_socket,
                    self.server_key,
                    self.storage_dir,
                    filename,
                    total_chunks,
                    event_callback=self.event_callback,
                )
            elif mode == SESSION_MODE_DOWNLOAD:
                file_path = self.storage_dir / Path(filename).name
                if not file_path.exists():
                    return MissingFileSession(
                        new_session_id,
                        self.server_socket,
                        self.server_key,
                        self.storage_dir,
                        filename,
                    )
                session = DownloadSession(
                    new_session_id,
                    self.server_socket,
                    self.server_key,
                    self.storage_dir,
                    filename,
                    event_callback=self.event_callback,
                )
            else:
                raise ValueError("unknown session mode")

            self.sessions[new_session_id] = session
            session.start()
            return session

    def serve_forever(self) -> None:
        print(f"Server listening on {self.host}:{self.port}")
        try:
            while self.running:
                packet, addr = self.server_socket.recvfrom(65535)
                try:
                    packet_type, _, _ = parse_header(packet)
                    if packet_type == PACKET_TYPE_LIST_FILES:
                        parse_list_files_packet(packet)
                        self.server_socket.sendto(build_list_response_packet(self.list_files()), addr)
                        continue
                    session = self.get_or_create_session(packet)
                    session.enqueue(packet, addr)
                except ValueError as exc:
                    print(f"Dropped packet from {addr}: {exc}")
        except KeyboardInterrupt:
            print("Shutting down.")
        except OSError:
            if self.running:
                raise
        finally:
            self.close()

    def close(self) -> None:
        if not self.running:
            return
        self.running = False
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.stop()
            close = getattr(session, "close", None)
            if callable(close):
                close()
            if session.is_alive():
                session.join(timeout=0.2)
        self.server_socket.close()

    def list_files(self) -> list[tuple[str, int]]:
        files: list[tuple[str, int]] = []
        for path in sorted(self.storage_dir.iterdir()):
            if path.is_file() and not path.name.startswith("."):
                files.append((path.name, path.stat().st_size))
        return files


class MissingFileSession(BaseSession):
    def __init__(self, session_id: int, server_socket: socket.socket, server_key, storage_dir: Path, filename: str) -> None:
        super().__init__(session_id, server_socket, server_key, storage_dir, filename, SESSION_MODE_DOWNLOAD)

    def handle_packet(self, packet: bytes, addr: tuple[str, int]) -> None:
        packet_type, _, _ = parse_header(packet)
        if packet_type != PACKET_TYPE_HELLO:
            raise ValueError("missing file session only handles hello")
        self.server_socket.sendto(
            build_hello_ack_packet(self.session_id, HELLO_STATUS_NOT_FOUND, 0, self.public_key),
            addr,
        )


def run_server(
    host: str,
    port: int,
    output_dir: str | None,
    event_callback: ServerEventCallback | None = None,
) -> None:
    ThreadedRUDPServer(host, port, output_dir, event_callback=event_callback).serve_forever()


def main() -> int:
    args = parse_args()
    run_server(args.host, args.port, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
