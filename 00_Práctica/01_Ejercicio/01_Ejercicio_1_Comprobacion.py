#XOR de datos binarios
def xor_data(binary_data_1, binary_data_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(binary_data_1, binary_data_2)])

# k2 es la clave fija que da el resultado del ejercicio de la parte 1
k1 = bytes.fromhex("B1EF2ACFE2BAEEFF")
k2 = bytes.fromhex("20553975C31055ED")

print(xor_data(k1,k2).hex())

K1=0xB1EF2ACFE2BAEEFF
K2=0x20553975C31055ED

Primary_key=(hex(K1^K2))

print(Primary_key[2:])