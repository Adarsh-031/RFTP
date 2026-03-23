import argparse
import socket
import tempfile
from pathlib import Path
from typing import Callable

from src.protocol import (
    CHUNK_SIZE,
    HELLO_STATUS_NOT_FOUND,
    HELLO_STATUS_OK,
    PACKET_TYPE_ACK,
    PACKET_TYPE_DATA,
    PACKET_TYPE_HELLO_ACK,
    PACKET_TYPE_KEY_ACK,
    PACKET_TYPE_LIST_RESPONSE,
    SESSION_MODE_DOWNLOAD,
    SESSION_MODE_UPLOAD,
    build_ack_packet,
    build_data_packet,
    build_hello_packet,
    build_key_packet,
    build_list_files_packet,
    build_missing_bitmap,
    chunk_file,
    parse_ack_packet,
    parse_data_packet,
    parse_header,
    parse_hello_ack_packet,
    parse_key_ack_packet,
    parse_list_response_packet,
)
from src.security import decrypt_chunk, encrypt_chunk, encrypt_session_key, generate_aes_key


ProgressCallback = Callable[[int, int], None]
StatusCallback = Callable[[str], None]


class TransferPaused(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RUDP Secure File Transfer Client")
    parser.add_argument("--host", required=True, help="Server address")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--upload-file", help="Local file to upload to the server")
    parser.add_argument("--download-file", help="Remote filename to download from the server")
    parser.add_argument("--save-path", help="Local path for downloaded file")
    parser.add_argument("--timeout", type=float, default=1.0, help="ACK timeout in seconds")
    parser.add_argument("--max-retries", type=int, default=5, help="Retransmissions per packet before reconnect")
    parser.add_argument("--max-resumes", type=int, default=3, help="Reconnect attempts for a dropped session")
    return parser.parse_args()


class SecureTransferClient:
    def __init__(
        self,
        sock: socket.socket,
        server_address: tuple[str, int],
        filename: str,
        mode: int,
        max_retries: int,
        max_resumes: int,
        progress_callback: ProgressCallback | None = None,
        status_callback: StatusCallback | None = None,
        timeout: float = 1.0,
    ) -> None:
        self.sock = sock
        self.server_address = server_address
        self.filename = filename
        self.mode = mode
        self.max_retries = max_retries
        self.max_resumes = max_resumes
        self.progress_callback = progress_callback
        self.status_callback = status_callback
        self.session_id = 0
        self.aes_key = generate_aes_key()
        self.total_chunks = 0
        self.pending_sequences: set[int] = set()
        self.paused = False
        self.timeout = timeout

    def replace_socket(self, sock: socket.socket) -> None:
        self.sock = sock
        self.sock.settimeout(self.timeout)

    def report_status(self, message: str) -> None:
        if self.status_callback is not None:
            self.status_callback(message)

    def report_progress(self) -> None:
        if self.progress_callback is None or self.total_chunks == 0:
            return
        completed = self.total_chunks - len(self.pending_sequences)
        self.progress_callback(completed, self.total_chunks)

    def pause(self) -> None:
        self.paused = True
        try:
            self.sock.close()
        except OSError:
            pass
        self.report_status("Paused")

    def resume(self) -> None:
        self.paused = False

    def ensure_not_paused(self) -> None:
        if self.paused:
            raise TransferPaused

    def perform_handshake(self) -> bytes:
        packet = build_hello_packet(
            self.session_id,
            self.mode,
            self.total_chunks,
            self.filename,
            build_missing_bitmap(self.total_chunks, self.pending_sequences) if self.total_chunks else b"",
        )

        for _ in range(self.max_retries):
            self.ensure_not_paused()
            self.sock.sendto(packet, self.server_address)
            try:
                response, _ = self.sock.recvfrom(65535)
                packet_type, _, _ = parse_header(response)
                if packet_type != PACKET_TYPE_HELLO_ACK:
                    continue
                session_id, status, total_chunks, public_key = parse_hello_ack_packet(response)
                if status == HELLO_STATUS_NOT_FOUND:
                    raise FileNotFoundError(self.filename)
                if status != HELLO_STATUS_OK:
                    raise RuntimeError("server rejected transfer request")
                self.session_id = session_id
                self.total_chunks = total_chunks
                if not self.pending_sequences:
                    self.pending_sequences = set(range(self.total_chunks))
                self.report_progress()
                return public_key
            except OSError:
                self.ensure_not_paused()
                continue
            except (socket.timeout, ValueError):
                continue

        raise TimeoutError("failed to complete server handshake")

    def exchange_session_key(self, public_key: bytes) -> None:
        packet = build_key_packet(self.session_id, encrypt_session_key(public_key, self.aes_key))
        for _ in range(self.max_retries):
            self.ensure_not_paused()
            self.sock.sendto(packet, self.server_address)
            try:
                response, _ = self.sock.recvfrom(65535)
                packet_type, session_id, _ = parse_header(response)
                if packet_type != PACKET_TYPE_KEY_ACK or session_id != self.session_id:
                    continue
                parse_key_ack_packet(response)
                return
            except OSError:
                self.ensure_not_paused()
                continue
            except (socket.timeout, ValueError):
                continue
        raise TimeoutError("failed to confirm AES session key")


class ReliableUploader(SecureTransferClient):
    def __init__(
        self,
        sock: socket.socket,
        server_address: tuple[str, int],
        file_path: str,
        max_retries: int,
        max_resumes: int,
        progress_callback: ProgressCallback | None = None,
        status_callback: StatusCallback | None = None,
        timeout: float = 1.0,
    ) -> None:
        self.file_path = file_path
        self.chunks = chunk_file(file_path)
        super().__init__(
            sock,
            server_address,
            Path(file_path).name,
            SESSION_MODE_UPLOAD,
            max_retries,
            max_resumes,
            progress_callback=progress_callback,
            status_callback=status_callback,
            timeout=timeout,
        )
        self.total_chunks = len(self.chunks)
        self.pending_sequences = {sequence for sequence, _, _ in self.chunks}
        self.report_progress()

    def send_chunk(self, sequence: int, payload: bytes, is_last: bool) -> bool:
        nonce, ciphertext, tag = encrypt_chunk(
            self.aes_key,
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
        for _ in range(self.max_retries):
            self.ensure_not_paused()
            self.sock.sendto(packet, self.server_address)
            try:
                response, _ = self.sock.recvfrom(65535)
                packet_type, session_id, _ = parse_header(response)
                if packet_type != PACKET_TYPE_ACK or session_id != self.session_id:
                    continue
                _, ack_sequence = parse_ack_packet(response)
                if ack_sequence == sequence:
                    return True
            except OSError:
                self.ensure_not_paused()
                continue
            except (socket.timeout, ValueError):
                continue
        return False

    def transfer(self) -> None:
        resume_attempts = 0
        while self.pending_sequences:
            if resume_attempts > self.max_resumes:
                raise TimeoutError("exhausted resume attempts for upload")
            self.ensure_not_paused()

            self.report_status(f"Uploading to {self.server_address[0]}:{self.server_address[1]}")
            public_key = self.perform_handshake()
            self.exchange_session_key(public_key)

            progress = False
            for sequence, payload, is_last in self.chunks:
                self.ensure_not_paused()
                if sequence not in self.pending_sequences:
                    continue
                if self.send_chunk(sequence, payload, is_last):
                    self.pending_sequences.remove(sequence)
                    progress = True
                    self.report_progress()
                    continue
                break

            if self.pending_sequences:
                resume_attempts += 1
                self.report_status(f"Upload reconnect, {len(self.pending_sequences)} chunks pending")
                if not progress:
                    continue

        self.report_status("Upload complete")


class ReliableDownloader(SecureTransferClient):
    def __init__(
        self,
        sock: socket.socket,
        server_address: tuple[str, int],
        remote_filename: str,
        save_path: str | None,
        max_retries: int,
        max_resumes: int,
        progress_callback: ProgressCallback | None = None,
        status_callback: StatusCallback | None = None,
        timeout: float = 1.0,
    ) -> None:
        super().__init__(
            sock,
            server_address,
            Path(remote_filename).name,
            SESSION_MODE_DOWNLOAD,
            max_retries,
            max_resumes,
            progress_callback=progress_callback,
            status_callback=status_callback,
            timeout=timeout,
        )
        self.save_path = Path(save_path) if save_path else Path(Path(remote_filename).name)
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        self.temp_file = tempfile.NamedTemporaryFile(
            mode="w+b",
            prefix=f"{self.save_path.name}-",
            suffix=".download",
            dir=str(self.save_path.parent),
            delete=False,
        )

    def write_chunk(self, sequence: int, payload: bytes) -> None:
        if sequence not in self.pending_sequences:
            return
        self.temp_file.seek(sequence * CHUNK_SIZE)
        self.temp_file.write(payload)
        self.temp_file.flush()
        self.pending_sequences.remove(sequence)
        self.report_progress()

    def receive_chunks(self) -> bool:
        while self.pending_sequences:
            self.ensure_not_paused()
            try:
                packet, _ = self.sock.recvfrom(65535)
            except OSError:
                self.ensure_not_paused()
                return False
            except socket.timeout:
                return False

            packet_type, session_id, _ = parse_header(packet)
            if packet_type != PACKET_TYPE_DATA or session_id != self.session_id:
                continue

            session_id, sequence, total_chunks, is_last, nonce, ciphertext, tag = parse_data_packet(packet)
            payload = decrypt_chunk(
                self.aes_key,
                session_id,
                sequence,
                total_chunks,
                is_last,
                nonce,
                ciphertext,
                tag,
            )
            self.write_chunk(sequence, payload)
            self.sock.sendto(build_ack_packet(self.session_id, sequence), self.server_address)

        return True

    def finalize(self) -> None:
        self.temp_file.close()
        self.save_path.parent.mkdir(parents=True, exist_ok=True)
        Path(self.temp_file.name).replace(self.save_path)

    def transfer(self) -> None:
        resume_attempts = 0
        try:
            while self.pending_sequences or self.total_chunks == 0:
                if resume_attempts > self.max_resumes:
                    raise TimeoutError("exhausted resume attempts for download")
                self.ensure_not_paused()

                self.report_status(f"Downloading from {self.server_address[0]}:{self.server_address[1]}")
                public_key = self.perform_handshake()
                self.exchange_session_key(public_key)
                if self.receive_chunks():
                    break

                resume_attempts += 1
                self.report_status(f"Download reconnect, {len(self.pending_sequences)} chunks pending")

            self.finalize()
            self.report_status(f"Download complete: {self.save_path}")
        except TransferPaused:
            raise
        except Exception:
            self.temp_file.close()
            temp_path = Path(self.temp_file.name)
            if temp_path.exists():
                temp_path.unlink()
            raise


def upload_file(
    sock: socket.socket,
    server_address: tuple[str, int],
    file_path: str,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    ReliableUploader(
        sock,
        server_address,
        file_path,
        max_retries,
        max_resumes,
        progress_callback=progress_callback,
        status_callback=status_callback,
        timeout=sock.gettimeout() or 1.0,
    ).transfer()


def download_file(
    sock: socket.socket,
    server_address: tuple[str, int],
    remote_filename: str,
    save_path: str | None,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    ReliableDownloader(
        sock,
        server_address,
        remote_filename,
        save_path,
        max_retries,
        max_resumes,
        progress_callback=progress_callback,
        status_callback=status_callback,
        timeout=sock.gettimeout() or 1.0,
    ).transfer()


def create_uploader(
    sock: socket.socket,
    server_address: tuple[str, int],
    file_path: str,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> ReliableUploader:
    return ReliableUploader(
        sock,
        server_address,
        file_path,
        max_retries,
        max_resumes,
        progress_callback=progress_callback,
        status_callback=status_callback,
        timeout=sock.gettimeout() or 1.0,
    )


def create_downloader(
    sock: socket.socket,
    server_address: tuple[str, int],
    remote_filename: str,
    save_path: str | None,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> ReliableDownloader:
    return ReliableDownloader(
        sock,
        server_address,
        remote_filename,
        save_path,
        max_retries,
        max_resumes,
        progress_callback=progress_callback,
        status_callback=status_callback,
        timeout=sock.gettimeout() or 1.0,
    )


def run_upload_client(
    host: str,
    port: int,
    file_path: str,
    timeout: float,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    if not Path(file_path).is_file():
        raise FileNotFoundError(f"file not found: {file_path}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        upload_file(
            sock,
            (host, port),
            file_path,
            max_retries,
            max_resumes,
            progress_callback=progress_callback,
            status_callback=status_callback,
        )
    finally:
        sock.close()


def run_download_client(
    host: str,
    port: int,
    remote_filename: str,
    save_path: str | None,
    timeout: float,
    max_retries: int,
    max_resumes: int,
    progress_callback: ProgressCallback | None = None,
    status_callback: StatusCallback | None = None,
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        download_file(
            sock,
            (host, port),
            remote_filename,
            save_path,
            max_retries,
            max_resumes,
            progress_callback=progress_callback,
            status_callback=status_callback,
        )
    finally:
        sock.close()


def list_server_files(host: str, port: int, timeout: float = 1.0) -> list[tuple[str, int]]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_list_files_packet(), (host, port))
        response, _ = sock.recvfrom(65535)
        packet_type, _, _ = parse_header(response)
        if packet_type != PACKET_TYPE_LIST_RESPONSE:
            raise ValueError("unexpected response to list request")
        return parse_list_response_packet(response)
    finally:
        sock.close()


def main() -> int:
    args = parse_args()
    if bool(args.upload_file) == bool(args.download_file):
        raise SystemExit("provide exactly one of --upload-file or --download-file")

    if args.upload_file:
        run_upload_client(
            args.host,
            args.port,
            args.upload_file,
            args.timeout,
            args.max_retries,
            args.max_resumes,
        )
    else:
        run_download_client(
            args.host,
            args.port,
            args.download_file,
            args.save_path,
            args.timeout,
            args.max_retries,
            args.max_resumes,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
