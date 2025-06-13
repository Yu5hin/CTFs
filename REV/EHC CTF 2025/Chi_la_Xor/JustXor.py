def Swap_Byte():
    with open("XorCoBan123.java", "rb") as f:
        enc = f.read()

    n = len(encrypt)
    data = bytearray(n)

    for i in range(0, n , 2):
        first = encrypt[i]
        second = encryp[i + 1]
        data[i] = second
        data[i + 1] = first

    with open("justXor", "wb") as f:
        f.write(data)


def Xor_Hex(data):
    n = len(data)
    result = bytearray(n)
    for i in range(n):
        if (i % 2 == 1):
            result[i] = data[i] ^ 0x16
        else:
            result[i] = data[i] ^ 0xC
    return result

encrypt = bytes.fromhex("49 5E 4F 42 4A 6D 4E 77 65 78 6D 6F 7D 63 6D 72 63 78 6B 7F 6D 78 7A 7F 62 79 6F 7E 65 4E 43 44 4C 56 4C 6B 00 00")
flag = xor(encrypt)
print(flag)
