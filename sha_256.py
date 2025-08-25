"""
SHA-256 Implementation
"""

import hashlib
import math
import argparse
import re
import numpy as np
from random_n_bits import GenerateRandom

__DEBUG_FLAG__ = False

# Constants
# SHA-256 use sixty-four constant 32-bit words
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initial Hash value
INIT_HASH = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def print_hex(data: bytearray):
    """
    Print the hexadecimal representation of a bytearray.
    """
    assert isinstance(data, bytearray), "Input must be a bytearray."

    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        print(f"{i:04x}: {hex_part}")

class SHACalc:
    """
    Base class for SHA hash calculations.
    """
    def __init__(self):
        # Set Properties (bits)
        self.block_size = 512  # 64 bytes
        self.word_size = 32  # 4 bytes

    def rotr(self, x:bytearray, n:int):
        """
        Rotate right function for SHA-256.
        """

        assert isinstance(x, bytearray), "Input must be a bytearray."

        n = n % self.word_size  # Ensure n is within the word size
        x = np.array(x, dtype=np.uint32)
        ret = ((x >> n) | (x << (self.word_size - n))) & 0xFFFFFFFF
        return ret

    def shr(self, x:bytearray, n:int):
        """
        Shift right function for SHA-256.
        """

        assert isinstance(x, bytearray), "Input must be a bytearray."

        n = n % self.word_size  # Ensure n is within the word size

        x = np.array(x, dtype=np.uint32)
        ret = (x >> n) & 0xFFFFFFFF

        return ret

    def rotl(self, x:bytearray, n:int):
        """
        Rotate left function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."

        n = n % self.word_size  # Ensure n is within the word size

        ret = ((x << n) | (x >> (self.word_size - n))) & 0xFFFFFFFF
        return ret

    def ch(self, x:bytearray, y:bytearray, z:bytearray):
        """
        Ch function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."
        assert isinstance(y, bytearray), "Input must be a bytearray."
        assert isinstance(z, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)
        y = np.array(y, dtype=np.uint32)
        z = np.array(z, dtype=np.uint32)

        ret = (x & y) ^ (~x & z)
        return ret

    def maj(self, x:bytearray, y:bytearray, z:bytearray):
        """
        Maj function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."
        assert isinstance(y, bytearray), "Input must be a bytearray."
        assert isinstance(z, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)
        y = np.array(y, dtype=np.uint32)
        z = np.array(z, dtype=np.uint32)

        ret = (x & y) ^ (x & z) ^ (y & z)
        return ret

    def sigma0(self, x:bytearray):
        """
        Sigma0 function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)

        ret = self.rotr(x, 7) ^ self.rotr(x, 18) ^ self.shr(x, 3)
        return ret

    def sigma1(self, x:bytearray):
        """
        Sigma1 function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)

        ret = self.rotr(x, 17) ^ self.rotr(x, 19) ^ self.shr(x, 10)
        return ret

    def cap_sigma0(self, x:bytearray):
        """
        CapSigma0 function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)

        ret = self.rotr(x, 2) ^ self.rotr(x, 13) ^ self.rotr(x, 22)
        return ret

    def cap_sigma1(self, x:bytearray):
        """
        CapSigma1 function for SHA-256.
        """
        assert isinstance(x, bytearray), "Input must be a bytearray."

        x = np.array(x, dtype=np.uint32)
        ret = self.rotr(x, 6) ^ self.rotr(x, 11) ^ self.shr(x, 25)
        return ret

class SHA256(SHACalc):
    """
    Implementation of the SHA-256 hash function.
    """
    def __init__(self, message = None, message_len = -1):
        super().__init__()
        self.block_size_bytes = self.block_size // 8
        self.word_size_bytes = self.word_size // 8
        assert message is not None, "Message must be provided."
        assert message_len > 0, "Message length must be positive."

        SHA256.init_hash = INIT_HASH.copy()
        SHA256.k = K.copy()
        self.message = message # in binary string
        self.message_len = message_len # bits length
        self.hash = SHA256.init_hash.copy()

        self.message_block = []


        self.block_n = math.ceil((self.message_len + 1 + 64) / self.block_size)

    @staticmethod
    def add32(x1:bytearray, x2:bytearray, x3:bytearray = None, 
            x4:bytearray = None, x5:bytearray = None):
        """
        Adds two 32-bit integers represented as bytearrays.
        """

        x_int = int.from_bytes(x1, 'big')
        y_int = int.from_bytes(x2, 'big')
        ret = (x_int + y_int) & 0xFFFFFFFF
        ret_byte = ret.to_bytes(4, 'big')

        if x3 is not None:
            ret = (ret + x3) & 0xFFFFFFFF
            ret_byte = ret.to_bytes(4, 'big')

        if x4 is not None:
            ret = (ret + x4) & 0xFFFFFFFF
            ret_byte = ret.to_bytes(4, 'big')

        if x5 is not None:
            ret = (ret + x5) & 0xFFFFFFFF
            ret_byte = ret.to_bytes(4, 'big')

        return ret_byte

    def pad(self):
        """
        SHA-256 padding (bit-string -> uint32 words, big-endian)
        self.message: '0'/'1'로만 이루어진 비트 문자열
        self.message_len: 원본 비트 길이 l
        """

        padded_len = 512 * self.block_n
        self.message = self.message + '1'

        for _ in range(padded_len - self.message_len - 1 - 64):
            self.message = self.message + '0'
        # type(self.message) = str

        byte_message = np.ndarray([], dtype=np.uint32)
        for _ in range(0, padded_len - 64, 8):
            b = self.message[_:_+8]
            v = int(b, 2)
            byte_message = np.append(byte_message, v)

        self.message = byte_message.copy()

        byte_len = np.ndarray(self.message_len.to_bytes(8, 'big'), dtype=np.uint64)
        #self.message = self.message + byte_len
        breakpoint()


    def parse(self):
        """
        Parsing function for SHA-256.
        """
        for i in range(self.block_n):
            tmp = []
            for j in range(0, self.block_size_bytes, self.word_size_bytes):
                w = self.message[i * self.block_size_bytes + j:
                                i * self.block_size_bytes + j + self.word_size_bytes]
                tmp.append(w)
            self.message_block.append(tmp)

    def preprocess(self):
        """
        Padding & Parsing for SHA-256.
        """

        assert self.message is not None, "Message must be set before preprocessing."
        assert self.message_len > 0, "Message length must be positive."
        assert isinstance(self.message, str), "Message must be a string."

        self.pad()
        self.parse()
        print("Preprocessing complete. Message blocks: ")
        for block in self.message_block:
            for i, word in enumerate(block):
                if i % 8 == 0:
                    print()
                print(f"\\x{word.hex()}", end=' ')
            print()
        breakpoint()
        return True

    def step1(self, iteration):
        """
        Step 1: Message Schedule Preparation
        """
        w_tmp = []
        for _i in range(64):
            if _i < 16:
                w_tmp.append(self.message_block[iteration][_i])
            else:
                s0 = super().sigma0(w_tmp[_i - 15])
                s1 = super().sigma1(w_tmp[_i - 2])
                wt_7 = self.message_block[iteration][_i - 7]
                wt_16 = self.message_block[iteration][_i - 16]
                _tmp = self.add32(s1, wt_7, s0, wt_16)
                w_tmp.append(_tmp)
        return w_tmp

    def step2(self, in_hash):
        """
        Step 2: Message Compression
        """
        ret_hash = in_hash.copy()
        return ret_hash

    def step3(self, w, in_hash):
        """
        Step 3: Finalization
        """
        a, b, c, d, e, f, g, h = in_hash
        for _i in range(64):
            t1 = self.add32(h, self.cap_sigma1(e), self.ch(e, f, g), K[_i], w[_i])
        pass

    def step4(self, iteration):
        """
        Step 4: Output
        """
        pass

    def compute_hash(self):
        """
        Compute the SHA-256 hash of the input message.
        """
        w = []
        for i in range(self.block_n):
            w = self.step1(i)
            self.hash = self.step2(self.hash)
            self.step3(w, self.hash)
            self.hash = self.step4(i)

        # Hash computation logic goes here
        return False
        breakpoint()
        return True

    def hashing(self) -> bytearray:
        """
        Generate the SHA-256 hash for the given message.
        """
        preprocess_success = False
        compute_success = False
        success = False

        preprocess_success = self.preprocess()
        compute_success = self.compute_hash()

        if preprocess_success and compute_success:
            success = True

        if not success:
            raise RuntimeError("Hash computation failed.")

        return self.hash

class ValidateHash:
    """
    A class to validate SHA-256 hashes.
    """
    def __init__(self, message, message_len):
        self.hashobject = hashlib.sha256()
        self.correct_value = None
        self.implementation = SHA256(message, message_len)
        self.message = None

    def correct_hash(self, message):
        """
        Compute the correct SHA-256 hash for the given message.
        """
        self.message = message
        self.hashobject.update(self.message)
        hex_dig = self.hashobject.hexdigest()
        print(hex_dig)  # Should print a 64-character hexadecimal string
        self.correct_value = hex_dig

        return hex_dig

    def validate_hash(self, message):
        """
        Validate the SHA-256 hash of the given message.
        """
        implement_hash = self.implementation.hashing()
        return implement_hash == self.correct_value

if __name__ == "__main__":

    # Argument parsing
    parser = argparse.ArgumentParser(description="SHA-256 Hash Generator")
    parser.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS,
                        help='Length of random bits to generate (default: 512)')
    parser.add_argument('-e', '--exponentiation', type=int, default=argparse.SUPPRESS,
                        help='2 to the power of <exponentiation> (default: 9)')
    parser.add_argument('-v', '--validate', action="store_true",
                        help='Validate the SHA-256 hash')
    parser.add_argument('-V', '--no-validate', action="store_false",
                        help='Do not validate the SHA-256 hash')
    c = parser.add_mutually_exclusive_group()
    d = parser.add_mutually_exclusive_group()

    c.add_argument('-c', '--clean_dir', action="store_true",
                dest='clean_dir', help='Directory to clean')
    c.add_argument('-C', '--no_clean_dir', action="store_false",
                dest='clean_dir', help='Directory to clean')
    d.add_argument('-d', '--debug', dest='debug',
                    action="store_true", help='Enable debug flag')
    d.add_argument('-D', '--no_debug', dest='debug',
                    action="store_false", help='Disable debug flag')

    c.set_defaults(clean_dir=False)
    d.set_defaults(debug=False)
    args = parser.parse_args()

    LENGTH = None
    if hasattr(args, 'length'):
        LENGTH = args.length
    else:
        pass

    if hasattr(args, 'exponentiation'):
        EXP = args.exponentiation
        LENGTH = 2 ** EXP
    else:
        pass

    __DEBUG_FLAG__ = args.debug
    print(__DEBUG_FLAG__)
    print(args.clean_dir)

    random_generator = GenerateRandom()

    try:
        setattr(random_generator, 'clear_flag', args.clean_dir)
    except AttributeError:
        print("AttributeError: Object has no attribute 'clear_flag'.")
    random_generator.file_clean()

    setattr(random_generator, 'length', 256)
    *data_256, len_rand_256 = random_generator.generate_random_bits()
    # setattr(random_generator, 'length', 447)
    # *data_447, len_rand_447 = random_generator.generate_random_bits()
    # setattr(random_generator, 'length', 448)
    # *data_448, len_rand_448 = random_generator.generate_random_bits()
    # setattr(random_generator, 'length', 512)
    # *data_512, len_rand_512 = random_generator.generate_random_bits()

    rand_256, bin_256, hex_256 = data_256
    # rand_447, bin_447, hex_447 = data_447
    # rand_448, bin_448, hex_448 = data_448
    # rand_512, bin_512, hex_512 = data_512

    print(f"256 bits: {rand_256}")
    # print(f"512 bits: {rand_512}")
    # print(f"447 bits: {rand_447}")
    # print(f"448 bits: {rand_448}")

    sha256 = SHA256(bin_256, len_rand_256)

    if LENGTH is not None:
        setattr(random_generator, 'length', LENGTH)
        rand_m, bin_m, hex_m, len_m = random_generator.generate_random_bits()
        res = setattr(sha256, bin_m, LENGTH)
    else:
        sha256.hashing()
