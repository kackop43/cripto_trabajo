from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512

# Identificador de dispositivo (salt) en hexadecimal | Para bytes
salt = bytes.fromhex("e43bb4067cbcfab3bec54437b84bef4623e345682d89de9948fbb0afedc461a3")

# Clave maestra del keystore con la etiqueta "cifrado-sim-aes-256" en hex | Para bytes
master_secret = bytes.fromhex("A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72")

# Derivar una clave AES-256 usando HKDF con SHA-512
aes_key = HKDF(master_secret, 32, salt, SHA512)  # Solo necesitamos optener una clave

# Imprimir la clave AES derivada en formato hexadecimal
print("Clave AES-256 derivada: ", aes_key.hex())
