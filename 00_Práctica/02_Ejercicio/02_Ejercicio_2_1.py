#AES/CBC/PKCS7
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode

# Datos proporcionados
key_hex = "A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72"
iv_hex = "00000000000000000000000000000000"
ciphertext_base64 = "TQ9SOMKc6aFS9SlxhfK9wT18UXpPCd505Xf5J/5nLI7Of/o0QKIWXg3nu1RRz4QWElezdrLAD5LO4USt3aB/i50nvvJbBiG+le1ZhpR84oI="

# Convertir clave, IV y mensaje cifrado a bytes
key = bytes.fromhex(key_hex)  # 32 bytes (256 bits)
iv = bytes.fromhex(iv_hex)    # 16 bytes (128 bits)
ciphertext = b64decode(ciphertext_base64)

# Configurar el descifrador
cipher = AES.new(key, AES.MODE_CBC, iv)

# Descifrar y quitar el padding PKCS7
plaintext_padded = cipher.decrypt(ciphertext)
plaintext = unpad(plaintext_padded, AES.block_size, style='pkcs7')  # Quitar padding

#Parte 1

# Imprimir el resultado
print("Mensaje descifrado (hex) con padding: ", plaintext_padded.hex())
print("Mensaje descifrado (hex) sin padding: ", plaintext.hex())
print("Mensaje descifrado (texto): ", plaintext.decode("utf-8"))
