from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import unhexlify

# Clave AES proporcionada (en hexadecimal) y convertir a bytes
clave_bytes = unhexlify("A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72")  

# 1. Calcular KCV(SHA-256)
sha256_hash = sha256(clave_bytes).digest()  # Calcular el hash SHA-256
kcv_sha256 = sha256_hash[:3]  # Los 3 primeros bytes
print(f"KCV(SHA-256): {kcv_sha256.hex().upper()}")

# 2. Calcular KCV(AES) en modo GCM
# Inicializar un bloque de 16 bytes con ceros
bloque_16_bytes = bytes(16)  # 16 bytes de ceros
iv = bytes(16)  # IV también de ceros (16 bytes de ceros)

# Crear el cifrador AES en modo GCM
cipher_aes_gcm = AES.new(clave_bytes, AES.MODE_GCM, nonce=iv)

# Cifrar el bloque y obtener el texto cifrado y la etiqueta de autenticación
cifrado, tag = cipher_aes_gcm.encrypt_and_digest(bloque_16_bytes)

# Obtener KCV(AES) de los primeros 3 bytes del resultado del cifrado
kcv_aes = cifrado[:3]
print(f"KCV(AES) en GCM: {kcv_aes.hex().upper()}")
