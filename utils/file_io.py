"""
File I/O Utilities
"""
from datetime import datetime
import os
import sys

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
data_path = os.path.join(project_root, "Data")
if data_path not in sys.path:
    sys.path.append(data_path)

# 고정 헤더 길이
TS_LEN = 32
BITLEN_LEN = 8 # 64 bits
PAD_LEN = 16 - BITLEN_LEN
HEADER_LEN = TS_LEN + BITLEN_LEN + PAD_LEN  # 48 bytes

class FILEio:
    """
    File I/O Utilities
    """
    def __init__(self, path="binary"):
        self.data_path = os.path.join(data_path, path)
        if not os.path.exists(self.data_path):
            os.makedirs(self.data_path)
        print(f"Data directory: {self.data_path}")

    @staticmethod
    def encode_timestamp() -> bytes:
        """
        로컬 시간 기준 "YYYY-MM-DD HH:MM:SS.ffffff" (26B)을 UTF-8로 넣고,
        나머지는 NUL(0x00)로 패딩해서 총 32바이트로 맞춘다.
        """
        dt = datetime.now().astimezone()

        # '+0900' 형태
        off = dt.strftime("%z")  # 예: '+0900'
        # '+09:00'로 변환
        tz = f"{off[:3]}:{off[3:]}"  # 길이 6

        s = f"{dt:%Y-%m-%d %H:%M:%S.%f}{tz}"  # 26 + 6 = 32
        # 방어적 체크
        if len(s) > 32:
            raise ValueError(f"timestamp length > 32: {s} (len={len(s)})")

        return s.encode("UTF-8")

    @staticmethod
    def encode_bit_length(bit_length: int) -> bytes:
        """
        Encode the bit length as a 64-bit unsigned integer in big-endian format.
        """
        return bit_length.to_bytes(8, byteorder='big')

    def file_clean(self, clear_flag = False):
        """
        Clean up the generated files.
        """
        if clear_flag:
            try:
                _dir = os.listdir(self.data_path)
                for file in _dir:
                    file_path = os.path.join(self.data_path, file)
                    os.remove(file_path)
                    print(f"Removed file: {file_path}")

            except IsADirectoryError as e:
                print(f"Error removing directory: {e}")

    def file_io(self, filename: str, ts: bytes = None):
        """
        Write the given data to a binary file.
        """
        def file_write(data):
            """
            Write the data to the file.
            """
            bytes_data, data_len = data
            try:
                with open(os.path.join(self.data_path, filename), "ab") as f:
                    pointer = f.tell()
                    if pointer % 16 != 0:
                        f.write(b'\x00' * (16 - pointer % 16))

                    _ts = self.encode_timestamp() if ts is None else ts
                    f.write(_ts) # Write timestamp (32 bytes)

                    _bit_length = self.encode_bit_length(data_len)
                    f.write(_bit_length)
                    f.write(b'\x00' * PAD_LEN)  # Write padding (for alignment)

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
            try:
                with open(os.path.join(self.data_path, filename), "rb") as f:
                    _ = f.read()

            except FileNotFoundError as e:
                print(f"File not found: {e}")

        return file_write, file_read
