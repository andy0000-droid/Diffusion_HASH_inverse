"""
SHA-256 Implementation
"""

import hashlib
import math
import argparse
import numpy as np
from random_n_bits import GenerateRandom

__DEBUG_FLAG__ = False

# Constants
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

class SHA256(SHACalc):
    """
    Implementation of the SHA-256 hash function.
    """
    def __init__(self):
        super().__init__()
        self.prev_hash = INIT_HASH.copy()
        self.message = None
        self.message_len = -1
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
        Adds two 32-bit integers represented as bytearrays.
        """
        ops_arr = [np.asarray(op, dtype=np.uint32) for op in ops]
        ret = np.add.reduce(ops_arr, dtype=np.uint32)

        return ret

    def pad(self):
        """
        SHA-256 padding (bit-string -> uint32 words, big-endian)
        self.message: '0'/'1'로만 이루어진 비트 문자열
        self.message_len: 원본 비트 길이 l
        """

        l = self.message_len
        assert set(self.message) <= {'0', '1'}

        # 1) k 계산: (l + 1 + k) ≡ 448 (mod 512)
        k = (448 - (l + 1)) % 512

        # 2) 패딩 비트 문자열 구성: 1비트 + k개의 0 + 64비트 길이
        padded_bits = self.message + '1' + ('0' * k) + format(l, '064b')
        # 총 길이는 512의 배수

        # 3) 비트 문자열 -> uint8 바이트
        bits = np.frombuffer(padded_bits.encode('ascii'), dtype=np.uint8) - ord('0')
        u8   = np.packbits(bits, bitorder='big')  # MSB-first로 압축

        # 4) 바이트 -> uint32 워드(빅엔디안)
        assert (u8.size % 4) == 0
        words_be = np.frombuffer(u8.tobytes(), dtype='>u4')  # shape: (#blocks*16,)

        # 5) 상태에 저장
        self.message = words_be.astype(np.uint32, copy=True)  # 워드 배열
        self.block_n = words_be.size // 16                    # 512비트 블록 수
        # breakpoint()


    def parse(self):
        """
        Parsing function for SHA-256.
        """
        for i in range(self.block_n):
            self.message_block.append(self.message[i * 16:(i + 1) * 16])

    def preprocess(self):
        """
        Padding & Parsing for SHA-256.
        """
        self.message_block = [] 
        assert self.message is not None, "Message must be set before preprocessing."
        assert self.message_len > 0, "Message length must be positive."
        assert isinstance(self.message, str), "Message must be a string."

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
        # breakpoint()
        return w_tmp

    def step2(self, _):
        """
        Step 2: Initialize working variables.
        """
        print("Step 2: Initialize working variables")

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

    def step4(self, work, in_hash):
        """
        Step 4: Finalize the hash value.
        """

        print("Step 4: Finalize the hash value")
        a,b,c,d,e,f,g,h = work
        return [
            self.add32(a, in_hash[0]), self.add32(b, in_hash[1]),
            self.add32(c, in_hash[2]), self.add32(d, in_hash[3]),
            self.add32(e, in_hash[4]), self.add32(f, in_hash[5]),
            self.add32(g, in_hash[6]), self.add32(h, in_hash[7]),
        ]


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
                self.step2(self.hash)
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

class ValidateHash:
    """
    A class to validate SHA-256 hashes.
    """
    def __init__(self):
        self.correct_value = None
        self.implementation = SHA256()
        self.message = None
        self.message_len = -1

    def correct_hash(self, message, message_len):
        """
        Compute the correct SHA-256 hash for the given message.
        """
        assert message is not None, "Message must be provided."
        assert message_len > 0, "Message length must be positive."
        h = hashlib.sha256()
        self.message = message
        self.message_len = message_len
        h.update(self.message)
        self.correct_value = h.hexdigest()
        print(f"Correct SHA-256 Hash: \n{self.correct_value}")
        for _i in range(0, len(self.correct_value), 8):
            print(f"Chunk {_i // 8}: {self.correct_value[_i:_i + 8]}")
        b = bytes.fromhex(self.correct_value)
        out = np.frombuffer(b, dtype='>u4').astype(np.uint32, copy=True)
        print(f"Correct HASH: \n{out}")
        return out

    def validate_hash(self, input_hash = None, message = None, message_len = -1):
        """
        Validate the SHA-256 hash of the given message.
        """

        print(f"Message: \n{message}")
        if input_hash is not None:
            _right_value = self.correct_hash(message, message_len)
            test_hash = input_hash
        else:
            _right_value = self.correct_hash(self.message, self.message_len)
            test_hash = self.implementation.hashing(self.message, self.message_len)

        print(f"Generated hash: \n{test_hash}")
        for _i, _test in enumerate(test_hash):
            if _test == _right_value[_i]:
                pass
            else:
                print("Hash validation failed.")
                return False

        print("Hash validation successful.")
        return True

if __name__ == "__main__":

    # Argument parsing
    parser = argparse.ArgumentParser(description="SHA-256 Hash Generator")
    parser.add_argument('-l', '--length', type=int, default=argparse.SUPPRESS,
                        help='Length of random bits to generate (default: 512)')
    parser.add_argument('-e', '--exponentiation', type=int, default=argparse.SUPPRESS,
                        help='2 to the power of <exponentiation> (default: 9)')
    parser.add_argument('-i', '--iteration', type=int, default=1,
                        help='Running iterations (default: 1)')

    gc = parser.add_mutually_exclusive_group()
    gc.add_argument('-c', '--clean_dir', action="store_true",
                dest='clean_dir', help='Directory to clean')
    gc.add_argument('-C', '--no_clean_dir', action="store_false",
                dest='clean_dir', help='Directory to clean')

    gc.set_defaults(clean_dir=False)
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

    print(f"Clean Directory: {args.clean_dir}")

    random_generator = GenerateRandom()

    try:
        setattr(random_generator, 'clear_flag', args.clean_dir)
    except AttributeError:
        print("AttributeError: Object has no attribute 'clear_flag'.")
    random_generator.file_clean()

    # pylint: disable=invalid-name
    rand_m = None
    bin_m = None
    hex_m = None
    len_m = None
    # pylint: enable=invalid-name

    # TODO
    # Add file output for the generated hashes
    # Add file output for intermediate values while processing

    if LENGTH is not None:
        for _ in range(args.iteration):
            sha256 = SHA256()
            validate_hash = ValidateHash()
            print(f"Iteration: {_ + 1}")

            setattr(random_generator, 'length', LENGTH)
            rand_m, bin_m, hex_m, len_m = random_generator.generate_random_bits()
            result_hash = sha256.hashing(bin_m, len_m)

            print("--------------Result--------------")
            print(f"Input bits ({len_m} bits): \n\\x{hex_m}\n")
            print("SHA-256 Hash: ")
            HEX_DIGEST = ''.join(f'{int(w):08x}' for w in result_hash)
            print(HEX_DIGEST)
            print("\n")

            print("--------------Validation--------------")
            valid_message = bytes.fromhex(hex_m)
            VALID = validate_hash.validate_hash(result_hash, valid_message, len_m)
            print("Correct SHA-256 Hash: ")
            print(f"Validation: {VALID}")

            if VALID:
                print(f"Hash validation succeeded at iteration {_ + 1}.")
            else:
                raise RuntimeError(f"Hash validation failed at iteration {_ + 1}.")

    else:
        sha256 = SHA256()
        setattr(random_generator, 'length', 256)
        *data_256, len_rand_256 = random_generator.generate_random_bits()
        rand_256, bin_256, hex_256 = data_256
        print(f"256 bits: {rand_256}")
        sha256.hashing(bin_256, len_rand_256)
