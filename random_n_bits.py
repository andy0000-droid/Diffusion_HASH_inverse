"""
Generate 512-bit random number and save it as binary file
"""
from secrets import randbits
from datetime import datetime
import argparse
import os
import math

# 고정 헤더 길이
TS_LEN = 32
BITLEN_LEN = 8 # 64 bits
PAD_LEN = 16 - BITLEN_LEN
HEADER_LEN = TS_LEN + BITLEN_LEN + PAD_LEN  # 48 bytes

class GenerateRandom:
    """
    Generate a random number of specified bit length.
    """
    def __init__(self, length=512, path="Data"):
        self.length = length # bits
        self._n = None
        self.bin_n = None
        self.hex_n = None
        self.path = os.path.join(os.getcwd(), path)
        self.ts = None
        self.clear_flag = False

        # Ensure the directory exists
        if not os.path.exists(self.path):
            os.makedirs(self.path, exist_ok=True)

    @staticmethod
    def print_hex(msg, x):
        """
        Print the hexadecimal representation of the given integer.
        """
        print(msg, end=": ")
        for _ in range(1, len(x), 2):
            print(f"\\x{x[_-1:_+1]}", end="")
        print()

    @staticmethod
    def print_bin(msg, x):
        """
        Print the binary representation of the given integer.
        """
        print(msg, end=": ")
        print(f"{x}")
        print()

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
        주어진 비트 길이를 8바이트(64비트)로 인코딩한다.
        """
        return bit_length.to_bytes(BITLEN_LEN, byteorder="big")

    def file_clean(self):
        """
        Clean up the generated files.
        """
        if self.clear_flag:
            try:
                _dir = os.listdir(self.path)
                for file in _dir:
                    file_path = os.path.join(self.path, file)
                    os.remove(file_path)
                    print(f"Removed file: {file_path}")
            except IsADirectoryError as e:
                print(f"Error removing directory: {e}")

    def file_io(self, filename: str, ts: bytes = None):
        """
        Write the given data to a binary file.
        """

        try:
            with open(os.path.join(self.path, filename), "ab") as f:
                pointer = f.tell()
                if pointer % 16 != 0:
                    f.write(b'\x00' * (16 - pointer % 16))
                _ts = self.encode_timestamp() if ts is None else ts
                f.write(_ts)

                _bit_length = self.encode_bit_length(self.length)
                print(f"Bits Length (dec): {self.length}, {_bit_length}")
                print(f"Bits Length (hex): {self.length:016x}, {_bit_length.hex()}")

                f.write(_bit_length)
                f.write(b'\x00' * PAD_LEN)  # Write padding
                f.write(bytes.fromhex(self.hex_n))  # Write hex data
        except FileNotFoundError as e:
            print(f"File not found: {e}")

    def generate_random_bits(self):
        """
        Generate a random 512-bit number and return its hexadecimal and binary representations.
        """
        self.ts = self.encode_timestamp()

        self._n = randbits(self.length)
        #print(f"Random Integer: \n{self._n}\n")

        self.bin_n = format(self._n, 'b').zfill(self.length)
        print(f"Integer to Binary: \n{self.bin_n}\n")
        self._n = self._n << (8 - (self.length % 8)) if self.length % 8 != 0 else self._n
        self.hex_n = hex(self._n)[2:].zfill(math.ceil(self.length / 4))
        print(f"Integer to Hexadecimal: \n{self.hex_n}\n")
        self.print_hex("Data in Hexadecimal", self.hex_n)

        assert len(self.bin_n) == self.length, "Binary length does not match specified length."

        print(f"Binary length in Bytes: \n{len(self.bin_n) / 8}\n") # type: str

        self.file_io(f"random_{self.length}_bits.bin")

        return self._n, self.bin_n, self.hex_n, self.length

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate random bits and save to a binary file.")
    parser.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS,
                        help='Length of random bits to generate (default: 512)')
    parser.add_argument('-i', '--iterations', type=int,
                        default=1, help='Number of iterations to run (default: 1)')
    parser.add_argument('-e', '--exponentiation', type=int, default=argparse.SUPPRESS,
                        help='2 to the power of <exponentiation> (default: 9)')
    args = parser.parse_args()

    LEN_FLAG = False
    EXP_FLAG = False

    if hasattr(args, 'length'):
        LENGTH = args.length
        LEN_FLAG = True

    else:
        LENGTH = 512

    if hasattr(args, 'exponentiation'):
        EXP = args.exponentiation
        EXP_FLAG = True
    else:
        EXP = 9

    BIT_LEN = None
    if LEN_FLAG:
        BIT_LEN = LENGTH

    elif EXP_FLAG:
        BIT_LEN = 2 ** EXP

    assert BIT_LEN is not None, "Either length or exponentiation must be specified."

    for _ in range(args.iterations):
        generator = GenerateRandom(BIT_LEN)
        # print(f"Iteration: {_ + 1}")
        # _bin, _ = generator.generate_random_bits()
        # print(f"Binary Representation: \n{_bin}\n")
