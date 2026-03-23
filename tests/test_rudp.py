import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from src.protocol import (
    ACK_HEADER,
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    CHUNK_SIZE,
    HELLO_STATUS_OK,
    PACKET_TYPE_HELLO,
    SESSION_MODE_DOWNLOAD,
    SESSION_MODE_UPLOAD,
    build_ack_packet,
    build_data_packet,
    build_hello_ack_packet,
    build_hello_packet,
    build_key_ack_packet,
    build_key_packet,
    build_list_files_packet,
    build_list_response_packet,
    build_missing_bitmap,
    chunk_bytes,
    chunk_file,
    parse_ack_packet,
    parse_data_packet,
    parse_header,
    parse_hello_ack_packet,
    parse_hello_packet,
    parse_key_ack_packet,
    parse_key_packet,
    parse_list_files_packet,
    parse_list_response_packet,
)
from src.security import (
    decrypt_chunk,
    decrypt_session_key,
    encrypt_chunk,
    encrypt_session_key,
    export_public_key,
    generate_aes_key,
    generate_server_rsa_key,
)
from src.udp_client import ReliableDownloader, ReliableUploader, TransferPaused, list_server_files
from src.udp_server import DownloadSession, ThreadedRUDPServer, UploadSession


class ProtocolTests(unittest.TestCase):
    def test_chunk_file_uses_1024_byte_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.bin"
            file_path.write_bytes(b"a" * (CHUNK_SIZE * 2 + 100))
            chunks = chunk_file(file_path)

        self.assertEqual(3, len(chunks))
        self.assertEqual(CHUNK_SIZE, len(chunks[0][1]))
        self.assertEqual(CHUNK_SIZE, len(chunks[1][1]))
        self.assertEqual(100, len(chunks[2][1]))
        self.assertTrue(chunks[2][2])

    def test_hello_packet_round_trip_with_mode(self) -> None:
        packet = build_hello_packet(
            11,
            SESSION_MODE_DOWNLOAD,
            10,
            "archive.zip",
            build_missing_bitmap(10, {0, 9}),
        )

        self.assertEqual(
            (11, SESSION_MODE_DOWNLOAD, 10, "archive.zip", {0, 9}),
            parse_hello_packet(packet),
        )

    def test_hello_ack_round_trip(self) -> None:
        packet = build_hello_ack_packet(12, HELLO_STATUS_OK, 9, b"public-key")

        self.assertEqual((12, HELLO_STATUS_OK, 9, b"public-key"), parse_hello_ack_packet(packet))

    def test_key_and_ack_packets_round_trip(self) -> None:
        key_packet = build_key_packet(9, b"encrypted")
        ack_packet = build_ack_packet(7, 9)

        self.assertEqual((9, b"encrypted"), parse_key_packet(key_packet))
        self.assertEqual(9, parse_key_ack_packet(build_key_ack_packet(9)))
        self.assertEqual(ACK_HEADER.size + 5, len(ack_packet))
        self.assertEqual((7, 9), parse_ack_packet(ack_packet))

    def test_data_packet_round_trip(self) -> None:
        packet = build_data_packet(5, 4, 7, False, b"n" * AES_GCM_NONCE_SIZE, b"cipher", b"t" * AES_GCM_TAG_SIZE)

        self.assertEqual(
            (5, 4, 7, False, b"n" * AES_GCM_NONCE_SIZE, b"cipher", b"t" * AES_GCM_TAG_SIZE),
            parse_data_packet(packet),
        )

    def test_list_files_round_trip(self) -> None:
        request = build_list_files_packet()
        response = build_list_response_packet([("alpha.txt", 3), ("beta.bin", 9)])

        self.assertIsNone(parse_list_files_packet(request))
        self.assertEqual([("alpha.txt", 3), ("beta.bin", 9)], parse_list_response_packet(response))


class SecurityTests(unittest.TestCase):
    def test_rsa_session_key_round_trip(self) -> None:
        server_key = generate_server_rsa_key()
        aes_key = generate_aes_key()
        encrypted_key = encrypt_session_key(export_public_key(server_key), aes_key)
        self.assertEqual(aes_key, decrypt_session_key(server_key, encrypted_key))

    def test_aes_gcm_chunk_round_trip(self) -> None:
        aes_key = generate_aes_key()
        nonce, ciphertext, tag = encrypt_chunk(aes_key, 3, 4, 8, False, b"payload")
        self.assertEqual(b"payload", decrypt_chunk(aes_key, 3, 4, 8, False, nonce, ciphertext, tag))


class UploaderTests(unittest.TestCase):
    def test_uploader_resumes_with_missing_bitmap_after_timeout(self) -> None:
        sock = Mock()
        server_key = generate_server_rsa_key()
        public_key = export_public_key(server_key)
        hello_1 = build_hello_ack_packet(321, HELLO_STATUS_OK, 2, public_key)
        key_ack_1 = build_key_ack_packet(321)
        ack_0 = build_ack_packet(321, 0)
        hello_2 = build_hello_ack_packet(321, HELLO_STATUS_OK, 2, public_key)
        key_ack_2 = build_key_ack_packet(321)
        ack_1 = build_ack_packet(321, 1)
        sent_packets: list[bytes] = []
        progress_events: list[tuple[int, int]] = []

        def record_send(packet: bytes, _addr: tuple[str, int]) -> None:
            sent_packets.append(packet)

        sock.sendto.side_effect = record_send
        sock.recvfrom.side_effect = [
            (hello_1, ("127.0.0.1", 9000)),
            (key_ack_1, ("127.0.0.1", 9000)),
            (ack_0, ("127.0.0.1", 9000)),
            socket.timeout(),
            (hello_2, ("127.0.0.1", 9000)),
            (key_ack_2, ("127.0.0.1", 9000)),
            (ack_1, ("127.0.0.1", 9000)),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.bin"
            file_path.write_bytes(b"a" * CHUNK_SIZE + b"tail")

            uploader = ReliableUploader(
                sock,
                ("127.0.0.1", 9000),
                str(file_path),
                max_retries=1,
                max_resumes=2,
                progress_callback=lambda done, total: progress_events.append((done, total)),
            )
            uploader.transfer()

        hello_packets = [packet for packet in sent_packets if parse_header(packet)[0] == PACKET_TYPE_HELLO]
        self.assertEqual((0, SESSION_MODE_UPLOAD, 2, "sample.bin", {0, 1}), parse_hello_packet(hello_packets[0]))
        self.assertEqual((321, SESSION_MODE_UPLOAD, 2, "sample.bin", {1}), parse_hello_packet(hello_packets[1]))
        self.assertEqual((0, 2), progress_events[0])
        self.assertEqual((2, 2), progress_events[-1])
        self.assertIn((1, 2), progress_events)

    def test_uploader_can_pause_before_transfer_loop(self) -> None:
        sock = Mock()
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.bin"
            file_path.write_bytes(b"abc")
            uploader = ReliableUploader(sock, ("127.0.0.1", 9000), str(file_path), max_retries=1, max_resumes=1)
            uploader.pause()
            with self.assertRaises(TransferPaused):
                uploader.transfer()


class UploadSessionTests(unittest.TestCase):
    def test_upload_session_stores_uploaded_file(self) -> None:
        server_socket = Mock()
        server_key = generate_server_rsa_key()

        with tempfile.TemporaryDirectory() as temp_dir:
            session = UploadSession(
                session_id=42,
                server_socket=server_socket,
                server_key=server_key,
                storage_dir=Path(temp_dir),
                filename="sample.bin",
                total_chunks=1,
            )
            hello = build_hello_packet(0, SESSION_MODE_UPLOAD, 1, "sample.bin", build_missing_bitmap(1, {0}))
            session.handle_packet(hello, ("127.0.0.1", 9000))
            hello_ack = server_socket.sendto.call_args_list[-1].args[0]
            self.assertEqual((42, HELLO_STATUS_OK, 1), parse_hello_ack_packet(hello_ack)[:3])

            aes_key = generate_aes_key()
            key_packet = build_key_packet(42, encrypt_session_key(parse_hello_ack_packet(hello_ack)[3], aes_key))
            session.handle_packet(key_packet, ("127.0.0.1", 9000))
            parse_key_ack_packet(server_socket.sendto.call_args_list[-1].args[0])

            nonce, ciphertext, tag = encrypt_chunk(aes_key, 42, 0, 1, True, b"payload")
            data_packet = build_data_packet(42, 0, 1, True, nonce, ciphertext, tag)
            session.handle_packet(data_packet, ("127.0.0.1", 9000))

            self.assertEqual(b"payload", (Path(temp_dir) / "sample.bin").read_bytes())


class DownloaderTests(unittest.TestCase):
    def test_downloader_reconstructs_server_file(self) -> None:
        sock = Mock()
        server_key = generate_server_rsa_key()
        public_key = export_public_key(server_key)
        payload = b"a" * CHUNK_SIZE + b"tail"
        chunks = chunk_bytes(payload)
        hello_ack = build_hello_ack_packet(777, HELLO_STATUS_OK, len(chunks), public_key)
        key_ack = build_key_ack_packet(777)
        aes_key = generate_aes_key()
        data_packets = []
        for sequence, chunk_payload, is_last in chunks:
            nonce, ciphertext, tag = encrypt_chunk(aes_key, 777, sequence, len(chunks), is_last, chunk_payload)
            data_packets.append(build_data_packet(777, sequence, len(chunks), is_last, nonce, ciphertext, tag))

        progress_events: list[tuple[int, int]] = []
        sent_packets: list[bytes] = []

        def record_send(packet: bytes, _addr: tuple[str, int]) -> None:
            sent_packets.append(packet)

        sock.sendto.side_effect = record_send
        sock.recvfrom.side_effect = [
            (hello_ack, ("127.0.0.1", 9000)),
            (key_ack, ("127.0.0.1", 9000)),
            (data_packets[0], ("127.0.0.1", 9000)),
            (data_packets[1], ("127.0.0.1", 9000)),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            save_path = Path(temp_dir) / "downloaded.bin"
            downloader = ReliableDownloader(
                sock,
                ("127.0.0.1", 9000),
                "downloaded.bin",
                str(save_path),
                max_retries=1,
                max_resumes=1,
                progress_callback=lambda done, total: progress_events.append((done, total)),
            )
            downloader.aes_key = aes_key
            downloader.transfer()

            self.assertEqual(payload, save_path.read_bytes())

        self.assertEqual([(0, 2), (1, 2), (2, 2)], progress_events)
        ack_packets = [packet for packet in sent_packets if parse_header(packet)[0] != PACKET_TYPE_HELLO]
        self.assertTrue(any(parse_header(packet)[0] == 6 for packet in ack_packets))

    def test_downloader_can_pause_before_transfer_loop(self) -> None:
        sock = Mock()
        with tempfile.TemporaryDirectory() as temp_dir:
            save_path = Path(temp_dir) / "downloaded.bin"
            downloader = ReliableDownloader(
                sock,
                ("127.0.0.1", 9000),
                "downloaded.bin",
                str(save_path),
                max_retries=1,
                max_resumes=1,
            )
            downloader.pause()
            with self.assertRaises(TransferPaused):
                downloader.transfer()

    def test_list_server_files_reads_catalog(self) -> None:
        fake_socket = Mock()
        fake_socket.recvfrom.return_value = (build_list_response_packet([("demo.txt", 12)]), ("127.0.0.1", 9000))

        original_socket = socket.socket
        socket.socket = Mock(return_value=fake_socket)
        try:
            self.assertEqual([("demo.txt", 12)], list_server_files("127.0.0.1", 9000))
        finally:
            socket.socket = original_socket


class ServerCatalogTests(unittest.TestCase):
    def test_server_lists_stored_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "alpha.txt").write_bytes(b"abc")
            (root / "beta.bin").write_bytes(b"012345")

            original_socket = socket.socket
            socket.socket = Mock(return_value=Mock())
            try:
                server = ThreadedRUDPServer("127.0.0.1", 0, str(root))
                self.assertEqual([("alpha.txt", 3), ("beta.bin", 6)], server.list_files())
                server.close()
            finally:
                socket.socket = original_socket


class DownloadSessionTests(unittest.TestCase):
    def test_download_session_stops_after_first_unacked_chunk(self) -> None:
        server_socket = Mock()
        server_key = generate_server_rsa_key()

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "video.bin"
            file_path.write_bytes(b"a" * CHUNK_SIZE + b"tail")

            session = DownloadSession(
                session_id=55,
                server_socket=server_socket,
                server_key=server_key,
                storage_dir=Path(temp_dir),
                filename="video.bin",
            )
            session.client_addr = ("127.0.0.1", 9000)
            session.session_key = generate_aes_key()

            session.send_chunks()

            self.assertEqual(5, server_socket.sendto.call_count)


if __name__ == "__main__":
    unittest.main()
