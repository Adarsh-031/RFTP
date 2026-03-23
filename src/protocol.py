import math
import struct
from pathlib import Path


CHUNK_SIZE = 1024
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16

PACKET_TYPE_HELLO = 1
PACKET_TYPE_HELLO_ACK = 2
PACKET_TYPE_KEY = 3
PACKET_TYPE_KEY_ACK = 4
PACKET_TYPE_DATA = 5
PACKET_TYPE_ACK = 6
PACKET_TYPE_LIST_FILES = 7
PACKET_TYPE_LIST_RESPONSE = 8

SESSION_MODE_UPLOAD = 1
SESSION_MODE_DOWNLOAD = 2

HELLO_STATUS_OK = 0
HELLO_STATUS_NOT_FOUND = 1

COMMON_HEADER = struct.Struct("!BI")
HELLO_HEADER = struct.Struct("!BIIH")
HELLO_ACK_HEADER = struct.Struct("!BIH")
KEY_HEADER = struct.Struct("!H")
DATA_HEADER = struct.Struct("!IIBH")
ACK_HEADER = struct.Struct("!I")
LIST_RESPONSE_HEADER = struct.Struct("!H")
LIST_ENTRY_HEADER = struct.Struct("!HI")
CHUNK_AAD = struct.Struct("!IIIB")


def chunk_file(file_path: str | Path, chunk_size: int = CHUNK_SIZE) -> list[tuple[int, bytes, bool]]:
    path = Path(file_path)
    data = path.read_bytes()
    return chunk_bytes(data, chunk_size)


def chunk_bytes(data: bytes, chunk_size: int = CHUNK_SIZE) -> list[tuple[int, bytes, bool]]:
    total_chunks = max(1, math.ceil(len(data) / chunk_size))
    chunks: list[tuple[int, bytes, bool]] = []

    if not data:
        return [(0, b"", True)]

    for sequence in range(total_chunks):
        start = sequence * chunk_size
        end = start + chunk_size
        payload = data[start:end]
        chunks.append((sequence, payload, sequence == total_chunks - 1))

    return chunks


def build_missing_bitmap(total_chunks: int, missing_sequences: set[int]) -> bytes:
    bitmap = bytearray(math.ceil(total_chunks / 8))
    for sequence in missing_sequences:
        if not 0 <= sequence < total_chunks:
            raise ValueError("sequence out of range for bitmap")
        byte_index = sequence // 8
        bit_index = 7 - (sequence % 8)
        bitmap[byte_index] |= 1 << bit_index
    return bytes(bitmap)


def parse_missing_bitmap(total_chunks: int, bitmap: bytes) -> set[int]:
    if total_chunks == 0:
        if bitmap:
            raise ValueError("bitmap not allowed when total_chunks is zero")
        return set()

    expected_size = math.ceil(total_chunks / 8)
    if len(bitmap) != expected_size:
        raise ValueError("invalid bitmap size")

    missing_sequences: set[int] = set()
    for sequence in range(total_chunks):
        byte_index = sequence // 8
        bit_index = 7 - (sequence % 8)
        if bitmap[byte_index] & (1 << bit_index):
            missing_sequences.add(sequence)
    return missing_sequences


def build_chunk_aad(session_id: int, sequence: int, total_chunks: int, is_last: bool) -> bytes:
    return CHUNK_AAD.pack(session_id, sequence, total_chunks, int(is_last))


def parse_header(packet: bytes) -> tuple[int, int, bytes]:
    if len(packet) < COMMON_HEADER.size:
        raise ValueError("packet too short for common header")
    packet_type, session_id = COMMON_HEADER.unpack(packet[: COMMON_HEADER.size])
    return packet_type, session_id, packet[COMMON_HEADER.size :]


def build_hello_packet(
    session_id: int,
    mode: int,
    total_chunks: int,
    filename: str,
    missing_bitmap: bytes,
) -> bytes:
    filename_bytes = filename.encode("utf-8")
    header = COMMON_HEADER.pack(PACKET_TYPE_HELLO, session_id)
    meta = HELLO_HEADER.pack(mode, total_chunks, len(missing_bitmap), len(filename_bytes))
    return header + meta + missing_bitmap + filename_bytes


def parse_hello_packet(packet: bytes) -> tuple[int, int, int, str, set[int]]:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_HELLO or len(body) < HELLO_HEADER.size:
        raise ValueError("invalid hello packet")

    mode, total_chunks, bitmap_length, filename_length = HELLO_HEADER.unpack(body[: HELLO_HEADER.size])
    end_of_bitmap = HELLO_HEADER.size + bitmap_length
    end_of_filename = end_of_bitmap + filename_length
    if len(body) != end_of_filename:
        raise ValueError("malformed hello packet")

    bitmap = body[HELLO_HEADER.size:end_of_bitmap]
    filename = body[end_of_bitmap:end_of_filename].decode("utf-8")
    return session_id, mode, total_chunks, filename, parse_missing_bitmap(total_chunks, bitmap)


def build_hello_ack_packet(session_id: int, status: int, total_chunks: int, public_key: bytes) -> bytes:
    return (
        COMMON_HEADER.pack(PACKET_TYPE_HELLO_ACK, session_id)
        + HELLO_ACK_HEADER.pack(status, total_chunks, len(public_key))
        + public_key
    )


def parse_hello_ack_packet(packet: bytes) -> tuple[int, int, int, bytes]:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_HELLO_ACK or len(body) < HELLO_ACK_HEADER.size:
        raise ValueError("invalid hello ACK packet")
    status, total_chunks, public_key_length = HELLO_ACK_HEADER.unpack(body[: HELLO_ACK_HEADER.size])
    public_key = body[HELLO_ACK_HEADER.size :]
    if len(public_key) != public_key_length:
        raise ValueError("malformed hello ACK packet")
    return session_id, status, total_chunks, public_key


def build_key_packet(session_id: int, encrypted_key: bytes) -> bytes:
    return COMMON_HEADER.pack(PACKET_TYPE_KEY, session_id) + KEY_HEADER.pack(len(encrypted_key)) + encrypted_key


def parse_key_packet(packet: bytes) -> tuple[int, bytes]:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_KEY or len(body) < KEY_HEADER.size:
        raise ValueError("invalid key packet")
    (key_length,) = KEY_HEADER.unpack(body[: KEY_HEADER.size])
    encrypted_key = body[KEY_HEADER.size :]
    if len(encrypted_key) != key_length:
        raise ValueError("malformed key packet")
    return session_id, encrypted_key


def build_key_ack_packet(session_id: int) -> bytes:
    return COMMON_HEADER.pack(PACKET_TYPE_KEY_ACK, session_id)


def parse_key_ack_packet(packet: bytes) -> int:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_KEY_ACK or body:
        raise ValueError("invalid key ACK packet")
    return session_id


def build_data_packet(
    session_id: int,
    sequence: int,
    total_chunks: int,
    is_last: bool,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError("invalid AES-GCM nonce size")
    if len(tag) != AES_GCM_TAG_SIZE:
        raise ValueError("invalid AES-GCM tag size")
    header = COMMON_HEADER.pack(PACKET_TYPE_DATA, session_id)
    meta = DATA_HEADER.pack(sequence, total_chunks, int(is_last), len(ciphertext))
    return header + meta + nonce + tag + ciphertext


def parse_data_packet(packet: bytes) -> tuple[int, int, int, bool, bytes, bytes, bytes]:
    packet_type, session_id, body = parse_header(packet)
    minimum_size = DATA_HEADER.size + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
    if packet_type != PACKET_TYPE_DATA or len(body) < minimum_size:
        raise ValueError("invalid data packet")

    sequence, total_chunks, last_flag, ciphertext_length = DATA_HEADER.unpack(body[: DATA_HEADER.size])
    nonce_start = DATA_HEADER.size
    nonce_end = nonce_start + AES_GCM_NONCE_SIZE
    tag_end = nonce_end + AES_GCM_TAG_SIZE
    ciphertext = body[tag_end:]
    if len(ciphertext) != ciphertext_length:
        raise ValueError("malformed data packet")

    nonce = body[nonce_start:nonce_end]
    tag = body[nonce_end:tag_end]
    return session_id, sequence, total_chunks, bool(last_flag), nonce, ciphertext, tag


def build_ack_packet(session_id: int, sequence: int) -> bytes:
    return COMMON_HEADER.pack(PACKET_TYPE_ACK, session_id) + ACK_HEADER.pack(sequence)


def parse_ack_packet(packet: bytes) -> tuple[int, int]:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_ACK or len(body) != ACK_HEADER.size:
        raise ValueError("invalid ACK packet")
    (sequence,) = ACK_HEADER.unpack(body)
    return session_id, sequence


def build_list_files_packet() -> bytes:
    return COMMON_HEADER.pack(PACKET_TYPE_LIST_FILES, 0)


def parse_list_files_packet(packet: bytes) -> None:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_LIST_FILES or session_id != 0 or body:
        raise ValueError("invalid list files packet")


def build_list_response_packet(files: list[tuple[str, int]]) -> bytes:
    entries = bytearray()
    for name, size in files:
        encoded = name.encode("utf-8")
        entries.extend(LIST_ENTRY_HEADER.pack(len(encoded), size))
        entries.extend(encoded)
    return (
        COMMON_HEADER.pack(PACKET_TYPE_LIST_RESPONSE, 0)
        + LIST_RESPONSE_HEADER.pack(len(files))
        + bytes(entries)
    )


def parse_list_response_packet(packet: bytes) -> list[tuple[str, int]]:
    packet_type, session_id, body = parse_header(packet)
    if packet_type != PACKET_TYPE_LIST_RESPONSE or session_id != 0 or len(body) < LIST_RESPONSE_HEADER.size:
        raise ValueError("invalid list response packet")

    (count,) = LIST_RESPONSE_HEADER.unpack(body[: LIST_RESPONSE_HEADER.size])
    offset = LIST_RESPONSE_HEADER.size
    files: list[tuple[str, int]] = []
    for _ in range(count):
        if len(body) < offset + LIST_ENTRY_HEADER.size:
            raise ValueError("malformed list response packet")
        name_length, size = LIST_ENTRY_HEADER.unpack(body[offset : offset + LIST_ENTRY_HEADER.size])
        offset += LIST_ENTRY_HEADER.size
        end = offset + name_length
        if len(body) < end:
            raise ValueError("malformed list response packet")
        files.append((body[offset:end].decode("utf-8"), size))
        offset = end
    if offset != len(body):
        raise ValueError("trailing bytes in list response packet")
    return files
