import ctypes, random, sys, os

rijndael = ctypes.CDLL('./rijndael.so')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'aes'))
import aes as py_aes

AES_BLOCK_SIZE_128 = 0
ByteArray16 = ctypes.c_ubyte * 16

# argtypes tells ctypes how to convert the arguments we pass to the C functions into the appropriate C types. 
rijndael.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
rijndael.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]

# test helpers
def rand_block():
    return [random.randint(0, 255) for _ in range(16)]

# test add_round_key
def test_add_round_key():
    print("Testing add_round_key...")
    for i in range(3):
        block_data = rand_block()
        key_data = rand_block()

        expected = bytes(b ^ k for b, k in zip(block_data, key_data))

        block = ByteArray16(*block_data)
        round_key = ByteArray16(*key_data)

        rijndael.add_round_key(block, round_key, AES_BLOCK_SIZE_128)

        result = bytes(block)

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Block:     {list(block_data)}\n"
            f" Round Key: {list(key_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("add_round_key: All tests passed!\n" + "-" * 38 + "\n")

# test sub_bytes
def test_sub_bytes():
    print("Testing sub_bytes...")
    for i in range(3):
        block_data = rand_block()

        block = ByteArray16(*block_data)
        rijndael.sub_bytes(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        # python version as boppreh expects the block to be a 4x4 matrix of bytes, so we need to convert it before calling sub_bytes
        py_block = [list(block_data[r*4:(r+1)*4]) for r in range(4)]
        py_aes.sub_bytes(py_block)
        expected = bytes([py_block[r][c] for r in range(4) for c in range(4)])

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("sub_bytes: All tests passed!\n" + "-" * 38 + "\n")

# test shift_rows
def test_shift_rows():
    print("Testing shift_rows...")
    for i in range(3):
        block_data = rand_block()
        
        block = ByteArray16(*block_data)
        rijndael.shift_rows(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        py_block = [list(block_data[r*4:(r+1)*4]) for r in range(4)]
        py_aes.shift_rows(py_block)
        expected = bytes([py_block[r][c] for r in range(4) for c in range(4)])

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("shift_rows: All tests passed!\n" + "-" * 38 + "\n")

# test mix_columns
def test_mix_columns():
    print("Testing mix_columns...")

    def xtime(x):
        return ((x << 1) ^ 0x1b) & 0xff if (x & 0x80) else (x << 1) & 0xff

    def py_mix_columns(block_data):
        result = list(block_data)
        for c in range(4):
            s0 = block_data[c * 4 + 0]
            s1 = block_data[c * 4 + 1]
            s2 = block_data[c * 4 + 2]
            s3 = block_data[c * 4 + 3]
            result[c * 4 + 0] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
            result[c * 4 + 1] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
            result[c * 4 + 2] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
            result[c * 4 + 3] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)
        return result
    
    for i in range(3):
        block_data = rand_block()

        block = ByteArray16(*block_data)
        rijndael.mix_columns(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        expected = bytes(py_mix_columns(block_data))


        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("mix_columns: All tests passed!\n" + "-" * 38 + "\n")

# test invert_sub_bytes
def test_invert_sub_bytes():
    print("Testing invert_sub_bytes...")
    for i in range(3):
        block_data = rand_block()

        block = ByteArray16(*block_data)
        rijndael.invert_sub_bytes(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        py_block = [list(block_data[r*4:(r+1)*4]) for r in range(4)]
        py_aes.inv_sub_bytes(py_block)
        expected = bytes([py_block[r][c] for r in range(4) for c in range(4)])

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("invert_sub_bytes: All tests passed!\n" + "-" * 38 + "\n")

def test_invert_shift_rows():
    print("Testing invert_shift_rows...")
    for i in range(3):
        block_data = rand_block()
        
        block = ByteArray16(*block_data)
        rijndael.invert_shift_rows(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        py_block = [list(block_data[r*4:(r+1)*4]) for r in range(4)]
        py_aes.inv_shift_rows(py_block)
        expected = bytes([py_block[r][c] for r in range(4) for c in range(4)])

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("invert_shift_rows: All tests passed!\n" + "-" * 38 + "\n")

# test invert_mix_columns
def test_invert_mix_columns():
    print("Testing invert_mix_columns...")

    def xtime(x):
        return ((x << 1) ^ 0x1b) & 0xff if (x & 0x80) else (x << 1) & 0xff
    
    def py_inv_mix_columns(block_data):
        result = list(block_data)
        for c in range(4):
            s0 = block_data[c * 4 + 0]
            s1 = block_data[c * 4 + 1]
            s2 = block_data[c * 4 + 2]
            s3 = block_data[c * 4 + 3]
            x2_0 = xtime(s0); x2_1 = xtime(s1); 
            x2_2 = xtime(s2); x2_3 = xtime(s3);
            x4_0=xtime(x2_0);  x4_1=xtime(x2_1)
            x4_2=xtime(x2_2);  x4_3=xtime(x2_3)
            x8_0=xtime(x4_0);  x8_1=xtime(x4_1)
            x8_2=xtime(x4_2);  x8_3=xtime(x4_3)
            result[c*4+0] = (x8_0^x4_0^x2_0)^(x8_1^x2_1^s1)^(x8_2^x4_2^s2)^(x8_3^s3)
            result[c*4+1] = (x8_0^s0)^(x8_1^x4_1^x2_1)^(x8_2^x2_2^s2)^(x8_3^x4_3^s3)
            result[c*4+2] = (x8_0^x4_0^s0)^(x8_1^s1)^(x8_2^x4_2^x2_2)^(x8_3^x2_3^s3)
            result[c*4+3] = (x8_0^x2_0^s0)^(x8_1^x4_1^s1)^(x8_2^s2)^(x8_3^x4_3^x2_3)
        return result
    for i in range(3):
        block_data = rand_block()

        block = ByteArray16(*block_data)
        rijndael.invert_mix_columns(block, AES_BLOCK_SIZE_128)
        result = bytes(block)

        expected = bytes(py_inv_mix_columns(block_data))

        assert result == expected, (
            f"Test {i+1} FAILED\n"
            f" Input:     {list(block_data)}\n"
            f" Expected:  {list(expected)}\n"
            f" Got:       {list(result)}"
        )
        print(f"Test {i+1} PASSED")
    print("invert_mix_columns: All tests passed!\n" + "-" * 38 + "\n")

# final end-to-end test of encryption and decryption
def test_encrypt_decrypt():
    print("Testing AES encryption and decryption...")
    for i in range(3):
        block_data = rand_block()
        key_data = rand_block()

        pt_bytes = bytes(block_data)
        key_bytes = bytes(key_data)

        # python reference implementation
        expected_ct = py_aes.AES(key_bytes).encrypt_block(pt_bytes)

        # C implementation
        block = ByteArray16(*block_data)
        key = ByteArray16(*key_data)
        ct_ptr = rijndael.aes_encrypt_block(block, key, AES_BLOCK_SIZE_128)
        result_ct = bytes(ct_ptr[:16])

        assert result_ct == expected_ct, (
            f"Encryption Test {i+1} FAILED\n"
            f" Plaintext: {list(block_data)}\n"
            f" Key:       {list(key_data)}\n"
            f" Expected:  {list(expected_ct)}\n"
            f" Got:       {list(result_ct)}"
        )

        # Now test decryption
        ct_block = ByteArray16(*result_ct)
        pt_ptr = rijndael.aes_decrypt_block(ct_block, key, AES_BLOCK_SIZE_128)
        result_pt = bytes(pt_ptr[:16])

        assert result_pt == pt_bytes, (
            f"Decryption Test {i+1} FAILED\n"
            f" Ciphertext: {list(result_ct)}\n"
            f" Key:        {list(key_data)}\n"
            f" Expected:   {list(pt_bytes)}\n"
            f" Got:        {list(result_pt)}"
        )
        print(f"Test {i+1} PASSED")
    print("AES encryption and decryption: All tests passed!\n" + "-" * 38 + "\n")

# Run the tests
if __name__ == "__main__":
    test_add_round_key()
    test_sub_bytes()
    test_shift_rows()
    test_mix_columns()
    test_invert_sub_bytes()
    test_invert_shift_rows()
    test_invert_mix_columns()
    test_encrypt_decrypt()