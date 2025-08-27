"""
File I/O Utilities
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
import os
from diffusion_hash_inv.utils.project_root import add_src_to_path, add_root_to_path
add_src_to_path()
ROOT_DIR = add_root_to_path()

# 고정 헤더 길이
TS_LEN = 32
BITLEN_LEN = 8 # 64 bits
PAD_LEN = 16 - BITLEN_LEN
HEADER_LEN = TS_LEN + BITLEN_LEN + PAD_LEN  # 48 bytes

def _encode_timestamp() -> bytes:
    dt = datetime.now().astimezone()
    tz = dt.strftime("%z")  # +0900
    tz = f"{tz[:3]}:{tz[3:]}"  # +09:00
    s = f"{dt:%Y-%m-%d %H:%M:%S.%f}{tz}"
    if len(s) != TS_LEN:
        raise ValueError(f"timestamp length != {TS_LEN}: {len(s)}")
    return s.encode("utf-8")

def _encode_bit_length(bit_length: int) -> bytes:
    if bit_length < 0:
        raise ValueError("bit_length must be >= 0")
    return bit_length.to_bytes(8, "big", signed=False)

def _decode_bit_length(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)

@dataclass
class Header:
    """
    Represents the header of a binary file.
    """
    timestamp_utf8: bytes  # 32B
    bit_length: int        # uint64
    reserved: bytes        # 8B

    @classmethod
    def now(cls, bit_length: int, timestamp: bytes = None) -> Header:
        """
        Create a new header with the current timestamp and the given bit length.
        """
        _timestamp = _encode_timestamp() if timestamp is None else timestamp
        return cls(_timestamp, bit_length, b"\x00" * PAD_LEN)

    def to_bytes(self) -> bytes:
        """
        Convert the header to bytes.
        """
        return self.timestamp_utf8 + _encode_bit_length(self.bit_length) + self.reserved

    @classmethod
    def from_file(cls, path: Path) -> Header:
        """
        Create a Header instance from a binary file.
        """
        with open(path, "rb") as f:
            raw = f.read(HEADER_LEN)
        if len(raw) != HEADER_LEN:
            raise ValueError("file too small to contain header")
        ts = raw[:TS_LEN]
        bl = _decode_bit_length(raw[TS_LEN:TS_LEN + BITLEN_LEN])
        rz = raw[TS_LEN + BITLEN_LEN:HEADER_LEN]
        return cls(ts, bl, rz)

class FileIO:
    """
    File I/O Utilities
    """
    def __init__(self):
        self.data_dir = ROOT_DIR / "data"
        self.out_dir = ROOT_DIR / "output"

    def file_clean(self, clear_flag = False):
        """
        Clean up the generated files.
        """
        if clear_flag:
            try:
                _dir = os.listdir(self.data_dir)
                for file in _dir:
                    file_path = os.path.join(self.data_dir, file)
                    os.remove(file_path)
                    print(f"Removed file: {file_path}")

            except IsADirectoryError as e:
                print(f"Error removing directory: {e}")

    def file_io(self, filename: str):
        """
        Write the given data to a binary file.
        """
        data_dir = None
        if filename.endswith(".bin"):
            bin_dir = self.data_dir / "binary"
            bin_dir.parent.mkdir(parents=True, exist_ok=True)
            data_dir = bin_dir
        if filename.endswith(".char"):
            char_dir = self.data_dir / "character"
            char_dir.parent.mkdir(parents=True, exist_ok=True)
            data_dir = char_dir

        assert data_dir is not None, "Invalid file extension. Use .bin or .char"

        def file_write(payload: bytes, ts: bytes = None):
            """
            Write the data to the file.
            """
            bytes_data, data_len = payload
            head = Header.now(data_len, ts)
            try:
                with open(data_dir / filename, "ab") as f:
                    pointer = f.tell()
                    if pointer % 16 != 0:
                        f.write(b'\x00' * (16 - pointer % 16))

                    f.write(head.to_bytes())
                    if isinstance(bytes_data, bytes):
                        f.write(bytes_data)
                    elif isinstance(bytes_data, str):
                        f.write(bytes.fromhex(bytes_data))  # Write hex data

                    pointer = f.tell()
                    if pointer % 16 != 0:
                        f.write(b'\x00' * (16 - pointer % 16))

            except FileNotFoundError as e:
                print(f"File not found: {e}")

        def file_read():
            """
            Read the data from the file.
            """
            read_path = self.out_dir / filename
            try:
                with open(read_path, "rb") as f:
                    _ = Header.from_file(read_path)
                    f.seek(HEADER_LEN)
                    _ = f.read()

            except FileNotFoundError as e:
                print(f"File not found: {e}")

        return file_write, file_read
