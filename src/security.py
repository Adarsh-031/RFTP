import os

from mbedtls import pk
from mbedtls.cipher import AES, MODE_GCM

from src.protocol import AES_GCM_NONCE_SIZE, build_chunk_aad


AES_KEY_SIZE = 32


def generate_server_rsa_key(key_size: int = 2048) -> pk.RSA:
    key = pk.RSA()
    key.generate(key_size=key_size)
    return key


def export_public_key(key: pk.RSA) -> bytes:
    return key.export_public_key()


def encrypt_session_key(public_key_bytes: bytes, aes_key: bytes) -> bytes:
    public_key = pk.RSA.from_buffer(public_key_bytes)
    return public_key.encrypt(aes_key)


def decrypt_session_key(private_key: pk.RSA, encrypted_key: bytes) -> bytes:
    return private_key.decrypt(encrypted_key)


def generate_aes_key() -> bytes:
    return os.urandom(AES_KEY_SIZE)


def encrypt_chunk(
    aes_key: bytes,
    session_id: int,
    sequence: int,
    total_chunks: int,
    is_last: bool,
    payload: bytes,
) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aad = build_chunk_aad(session_id, sequence, total_chunks, is_last)
    cipher = AES.new(aes_key, MODE_GCM, iv=nonce, ad=aad)
    ciphertext, tag = cipher.encrypt(payload)
    return nonce, ciphertext, tag


def decrypt_chunk(
    aes_key: bytes,
    session_id: int,
    sequence: int,
    total_chunks: int,
    is_last: bool,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    aad = build_chunk_aad(session_id, sequence, total_chunks, is_last)
    cipher = AES.new(aes_key, MODE_GCM, iv=nonce, ad=aad)
    return cipher.decrypt(ciphertext, tag)
