import ctypes, random, sys, os

rijndael = ctypes.CDLL('./rijndael.so')

AES_BLOCK_SIZE_128 = 0
ByteArray16 = ctypes.c_ubyte * 16

rijndael.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]

def rand_block():
    return [random.randint(0, 255) for _ in range(16)]

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
    print("add_round_key: All tests passed!")


# Run the tests
if __name__ == "__main__":
    test_add_round_key()