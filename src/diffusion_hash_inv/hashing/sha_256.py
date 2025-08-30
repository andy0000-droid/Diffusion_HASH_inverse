"""
SHA-256 Implementation
"""

# TODO
# Add file output for the generated hashes
# Add file output for intermediate values while processing
# Time logging for performance measurement

import hashlib
import math
import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from functools import wraps

import numpy as np

def get_project_root(marker_files=("pyproject.toml", ".git")) -> Path:
    """
    Jupyter/Script 어디서 실행해도 프로젝트 루트를 찾아줌.
    marker_files 중 하나라도 있으면 거기를 루트로 간주.
    """
    current = Path.cwd().resolve()  # notebook에서는 cwd 기준
    for parent in [current, *current.parents]:
        if any((parent / marker).exists() for marker in marker_files):
            return parent
    raise FileNotFoundError("프로젝트 루트를 찾을 수 없습니다.")
def add_src_to_path():
    """프로젝트 루트 밑의 src/를 sys.path에 자동 추가"""
    root = get_project_root()
    src = root / "src"

    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    return src

add_src_to_path()

try:
    from diffusion_hash_inv.generator.random_n_bits import GenerateRandom
except ImportError as e:
    print(f"Error importing GenerateRandom: {e}")

try:
    from diffusion_hash_inv.generator.random_n_char import GenerateRandomNChar
except ImportError as e:
    print(f"Error importing GenerateRandomNChar: {e}")

try:
    from diffusion_hash_inv.utils import FileIO
except ImportError as e:
    print(f"Error importing FileIO: {e}")

@dataclass
class OutputFormat:
    """
    Class to handle output formatting for SHA-256 hash results.
    """
    func_name: str
    l1_data: list = field(default_factory=list)
    l2_data: list = field(default_factory=list)
    l3_data: list = field(default_factory=list)

    def b2hex(self):
        """
        Convert the message bytes to a hexadecimal string.
        """
        assert self.message is not None, "Message data is not set."
        return self.message.hex()

    def save_json(self):
        """
        Save the hash results to a JSON file.
        """
        assert self.message is not None, "Message data is not set."
        assert self.l1_data is not None, "L1 data is not set."
        assert self.l2_data is not None, "L2 data is not set."
        assert self.l3_data is not None, "L3 data is not set."

        output = {
            "message": self.message.hex(),
            "message_len": self.message_len,
            "l1_data": self.l1_data,
            "l2_data": self.l2_data,
            "l3_data": self.l3_data,
        }
        return output

def json_logger(func: callable):
    """
    JSON logger decorator for functions.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(f"{func.__name__} called")
        result = func(*args, **kwargs)
        log_data = {
            "function": func.__name__,
            "result": result
        }
        breakpoint()
        print(json.dumps(log_data))
        return result

    return wrapper    

# Constants start
# SHA-256 use sixty-four constant 32-bit words
K = np.array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
], dtype=np.uint32)

# Initial Hash value
INIT_HASH = np.array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
], dtype=np.uint32)
# Constants end

# Internal Operations of the SHA-256 algorithm start
class SHACalc:
    """
    Base class for SHA hash calculations.
    """
    def __init__(self):
        # Set Properties (bits)
        self.block_size = 512  # 64 bytes
        self.word_size = 32  # 4 bytes
        self.block_size_bytes = self.block_size // 8
        self.word_size_bytes = self.word_size // 8
        self.mask = np.uint32(0xFFFFFFFF)

    def rotr(self, x:np.uint32, n:int):
        """
        Rotate right function for SHA-256.
        """

        assert isinstance(x, np.uint32), "Input must be a np.uint32 (rotr)."

        n = n % self.word_size  # Ensure n is within the word size
        right = x >> n
        left = (x << (self.word_size - n)) & self.mask
        ret = (left | right) & self.mask
        return ret

    def shr(self, x:np.uint32, n:int):
        """
        Shift right function for SHA-256.
        """

        assert isinstance(x, np.uint32), "Input must be a np.uint32 (shr)."

        n = n % self.word_size  # Ensure n is within the word size
        ret = (x >> n) & self.mask

        return ret

    def ch(self, x:np.uint32, y:np.uint32, z:np.uint32):
        """
        Ch function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (ch)."
        assert isinstance(y, np.uint32), "Input must be a np.uint32 (ch)."
        assert isinstance(z, np.uint32), "Input must be a np.uint32 (ch)."

        ret = ((x & y) ^ (~x & z)) & self.mask
        return ret

    def maj(self, x:np.uint32, y:np.uint32, z:np.uint32):
        """
        Maj function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (maj)."
        assert isinstance(y, np.uint32), "Input must be a np.uint32 (maj)."
        assert isinstance(z, np.uint32), "Input must be a np.uint32 (maj)."

        ret = ((x & y) ^ (x & z) ^ (y & z)) & self.mask
        return ret

    def sigma0(self, x:np.uint32):
        """
        Sigma0 function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (sigma0)."

        ret = (self.rotr(x, 7) ^ self.rotr(x, 18) ^ self.shr(x, 3)) & self.mask
        return ret

    def sigma1(self, x:np.uint32):
        """
        Sigma1 function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (sigma1)."

        ret = (self.rotr(x, 17) ^ self.rotr(x, 19) ^ self.shr(x, 10)) & self.mask
        return ret

    def cap_sigma0(self, x:np.uint32):
        """
        CapSigma0 function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (cap_sigma0)."

        ret = (self.rotr(x, 2) ^ self.rotr(x, 13) ^ self.rotr(x, 22)) & self.mask
        return ret

    def cap_sigma1(self, x:np.uint32):
        """
        CapSigma1 function for SHA-256.
        """
        assert isinstance(x, np.uint32), "Input must be a np.uint32 (cap_sigma1)."

        ret = (self.rotr(x, 6) ^ self.rotr(x, 11) ^ self.rotr(x, 25)) & self.mask
        return ret
# Internal Operations of the SHA-256 algorithm end

# Implementation of the SHA-256 algorithm start
class SHA256(SHACalc):
    """
    Implementation of the SHA-256 hash function.
    """
    def __init__(self):
        super().__init__()
        self.prev_hash = INIT_HASH.copy()
        self.message = None # in bytes
        self.message_len = -1 # in bits
        self.hash = None

        self.message_block = []

        self.block_n = math.ceil((self.message_len + 1 + 64) / self.block_size)

    def reset(self):
        """각 해시 계산 시작 시 내부 상태 초기화"""
        self.prev_hash = INIT_HASH.copy()
        self.hash = None
        self.message_block = []
        self.block_n = 0

    @staticmethod
    def add32(*ops):
        """
        Adds multiple np.uint32 numbers with modulo 2^32.
        """
        ops_arr = [np.asarray(op, dtype=np.uint32) for op in ops]
        ret = np.add.reduce(ops_arr, dtype=np.uint32)

        return ret

    def pad(self):
        """
        SHA-256 padding (bytearray -> uint32 words, big-endian)
        self.message: bytearray
        self.message_len: 원본 비트 길이 l
        """

        l = len(self.message)
        self.message = bytearray(self.message)  # Ensure message is a bytearray
        self.message += b'\x80'  # Append the bit '1' (0x80 in hex)
        pad_zero_len = (56 - (l + 1) % 64) % 64
        self.message += b'\x00' * pad_zero_len

        # Append the original message length in bits (64 bits)
        self.message += self.message_len.to_bytes(8, byteorder='big')
        words_be = np.frombuffer(self.message, dtype='>u4')
        self.message = words_be.astype(np.uint32, copy=True)  # 워드 배열
        self.block_n = self.message.size // 16

    def parse(self):
        """
        Parsing function for SHA-256.
        """
        for i in range(self.block_n):
            self.message_block.append(self.message[i * 16:(i + 1) * 16])

    @json_logger
    def preprocess(self):
        """
        Padding & Parsing for SHA-256.
        """
        self.message_block = []
        assert self.message is not None, "Message must be set before preprocessing."
        assert self.message_len > 0, "Message length must be positive."
        assert isinstance(self.message, (bytearray, bytes)), "Message must be a bytearray."

        self.pad()
        self.parse()
        print("Preprocessing complete. Message blocks: ")
        for i, block in enumerate(self.message_block):
            print(f"Block {i}:")
            for j, word in enumerate(block):
                if j % 8 == 0 and j != 0:
                    print()
                print(f"\\x{hex(word):010}", end=' ')
            print()
        print()
        # breakpoint()
        return True
    @json_logger
    def step1(self, iteration):
        """
        Step 1: Message Schedule Preparation
        """
        print("Step 1: Message Schedule Preparation")

        w_tmp = []
        for _i in range(64):
            if _i < 16:
                w_tmp.append(self.message_block[iteration][_i])
            else:
                s0 = super().sigma0(w_tmp[_i - 15])
                s1 = super().sigma1(w_tmp[_i - 2])
                wt_7 = w_tmp[_i - 7]
                wt_16 = w_tmp[_i - 16]
                _tmp = self.add32(s1, wt_7, s0, wt_16)
                w_tmp.append(_tmp)

        return w_tmp

    @json_logger
    def step2(self, in_hash):
        """
        Step 2: Initialize working variables.
        """
        print("Step 2: Initialize working variables")
        a, b, c, d, e, f, g, h = in_hash
        return [a, b, c, d, e, f, g, h]

    @json_logger
    def step3(self, w, in_hash):
        """
        Step 3: Main compression function loop.
        """
        print("Step 3: Main compression function loop")

        a, b, c, d, e, f, g, h = in_hash
        for _i in range(64):
            t1 = self.add32(h, self.cap_sigma1(e), super().ch(e, f, g), K[_i], w[_i])
            t2 = self.add32(self.cap_sigma0(a), super().maj(a, b, c))
            h = g
            g = f
            f = e
            e = self.add32(d, t1)
            d = c
            c = b
            b = a
            a = self.add32(t1, t2)
        # breakpoint()
        return [a, b, c, d, e, f, g, h]

    @json_logger
    def step4(self, work, in_hash):
        """
        Step 4: Finalize the hash value.
        """

        print("Step 4: Finalize the hash value")
        a,b,c,d,e,f,g,h = work
        res = [
            self.add32(a, in_hash[0]), self.add32(b, in_hash[1]),
            self.add32(c, in_hash[2]), self.add32(d, in_hash[3]),
            self.add32(e, in_hash[4]), self.add32(f, in_hash[5]),
            self.add32(g, in_hash[6]), self.add32(h, in_hash[7]),
        ]
        return res

    def compute_hash(self):
        """
        Compute the SHA-256 hash of the input message.
        """
        w = []
        try:
            for _i in range(self.block_n):
                # pylint: disable=line-too-long
                print(f"\nProcessing {_i + 1} block of {self.block_n} blocks ({_i / self.block_n * 100:.2f}%)")
                # pylint: enable=line-too-long
                w = self.step1(_i)
                self.prev_hash = self.step2(self.prev_hash)
                out = self.step3(w, self.prev_hash)
                self.hash = self.step4(out, self.prev_hash)
                self.prev_hash = self.hash

            # breakpoint()
            return True

        # pylint: disable=broad-exception-caught
        except Exception as e:
            print(f"Error during hash computation: {e}")
            return False
        # pylint: enable=broad-exception-caught

    def finalize(self):
        """
        Finalize the hash computation and return the final hash value.
        """
        # breakpoint()

        a,b,c,d,e,f,g,h = (np.uint32(x) for x in self.hash)
        out = np.array([a,b,c,d,e,f,g,h], dtype=np.uint32)
        return out

    def hashing(self, message = None, message_len = -1) -> bytearray:
        """
        Generate the SHA-256 hash for the given message.
        """
        assert message is not None, "Message must be provided."
        assert isinstance(message, (bytes, bytearray, str)), "Message must be bytes or bytearray."
        assert message_len > 0, "Message length must be positive."

        self.message = message # in binary string
        self.message_len = message_len

        preprocess_success = False
        compute_success = False
        success = False

        preprocess_success = self.preprocess()
        print("Preprocessing successful")
        # breakpoint()
        compute_success = self.compute_hash()
        print("Computation successful")

        if preprocess_success and compute_success:
            success = True
            result = self.finalize()
            return result

        if not success:
            raise RuntimeError("Hash computation failed.")
        return None
# Implementation of the SHA-256 algorithm end

# Implementation of the SHA-256 hash validation start
class ValidateHash:
    """
    A class to validate SHA-256 hashes.
    """
    def __init__(self):
        self._right_value = None
        self.implementation = SHA256()

    def correct_hash(self, message, message_len):
        """
        Compute the correct SHA-256 hash for the given message.
        """
        assert message is not None, "Message must be provided."
        assert message_len > 0, "Message length must be positive."
        h = hashlib.sha256()
        h.update(message)
        return h.hexdigest()

    def validate_hash(self, input_hash = None, message = None, message_len = -1):
        """
        Validate the SHA-256 hash of the given message.
        """

        print(f"Message: \n{message}")
        if input_hash is not None:
            _right_value = self.correct_hash(message, message_len)
            test_hash = input_hash
        else:
            raise ValueError("Input hash must be provided.")

        print(f"Correct SHA-256 Hash: \n{_right_value}")
        for _i in range(0, len(_right_value), 8):
            print(f"Chunk {_i // 8}: {_right_value[_i:_i + 8]}")
        b = bytes.fromhex(_right_value)
        out = np.frombuffer(b, dtype='>u4').astype(np.uint32, copy=True)
        print(f"Correct HASH: \n{out}")

        print(f"Generated hash: \n{test_hash}")
        for _i, _test in enumerate(test_hash):
            if _test == out[_i]:
                pass
            else:
                print("Hash validation failed.")
                return False

        print("Hash validation successful.")
        return True
# Implementation of the SHA-256 hash validation end

# pylint: disable=too-many-locals
def main(*flags: bool, length: int = 512, iteration: int = 1):
    """
    Main function to execute the SHA-256 hash generation and validation.
    """
    assert length > 0, "Length must be positive."
    assert iteration > 0, "Iteration count must be positive."
    m_flag, v_flag, c_flag = flags
    file_io = FileIO()
    sha256 = SHA256()
    validate_hash = ValidateHash()
    random_generator = GenerateRandom(c_flag, v_flag)
    random_generator = GenerateRandomNChar(c_flag, v_flag)
    f_w, _ = file_io.file_io("sha256_hashes.json")

    for _ in range(iteration):
        sha256.reset()
        print(f"Iteration: {_ + 1}")
        if not m_flag:
            byte_m = random_generator.generate_random_bits(length)
        else:
            byte_m = random_generator.main(length // 8)

        print(f"Iteration: {_ + 1}")
        result_hash = sha256.hashing(byte_m, len(byte_m) * 8)

        print(f"----------------Result for iteration ({_ + 1})----------------")
        print(f"Input bits ({len(byte_m) * 8} bits): \n{byte_m}\n")
        print("SHA-256 Hash: ")
        hex_digest = ''.join(f'{int(w):08x}' for w in result_hash)
        print(hex_digest)
        print("\n")

        print(f"--------------Validation for iteration ({_ + 1})--------------")
        valid = validate_hash.validate_hash(result_hash, byte_m, len(byte_m) * 8)
        print("Correct SHA-256 Hash: ")
        valid_message = "Failed" if not valid else "Succeeded"
        print(f"Validation: {valid_message}")

        if valid:
            print(f"Hash validation succeeded at iteration {_ + 1}.")
            print("===================================\n")
        else:
            raise RuntimeError(f"Hash validation failed at iteration {_ + 1}.")


if __name__ == "__main__":

    # Argument parsing
    parser = argparse.ArgumentParser(description="SHA-256 Hash Generator")
    parser.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS,
                        help='Length of random bits to generate (default: 512)')
    parser.add_argument('-e', '--exponentiation', type=int, default=argparse.SUPPRESS,
                        help='2 to the power of <exponentiation> (default: 9)')
    parser.add_argument('-i', '--iteration', type=int, default=1,
                        help='Running iterations (default: 1)')

    gv = parser.add_mutually_exclusive_group()
    gv.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                    help='Enable verbose output')
    gv.add_argument('-q', '--quiet', action='store_false', dest='verbose',
                    help='Suppress output')
    parser.set_defaults(verbose=True)

    gm = parser.add_mutually_exclusive_group()
    gm.add_argument('-m', '--message', action="store_true",
                    dest='message', help='Message input mode')
    gm.add_argument('-b', '--bit', action="store_false",
                    dest='message', help='Bit string input mode')
    parser.set_defaults(message=True)

    gc = parser.add_mutually_exclusive_group()
    gc.add_argument('-c', '--clear', action='store_true',
                    dest='clear', help='Clear generated files')
    gc.add_argument('-C', '--no-clear', action='store_true', dest='clear',
                    help='Do not clear generated files (default)')
    parser.set_defaults(clear=False)
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

    main(args.message, args.verbose, args.clear, length=LENGTH, iteration=args.iteration)
