import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Cifrado
textoPlano_bytes = bytes('KeepCoding es una pasadaa hala', 'UTF-8')
clave = bytes.fromhex('E2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72')
iv_bytes = bytes.fromhex('00000000000000000000000000000000')

# Crear el objeto de cifrado
cipher = AES.new(clave, AES.MODE_CBC, iv_bytes)

# Aplicar padding
mensaje_padding = pad(textoPlano_bytes, AES.block_size, style='x923')

# Mostrar el mensaje con padding aplicado
print("Texto plano con padding (hex):", mensaje_padding.hex())

# Cifrar
texto_cifrado_bytes = cipher.encrypt(mensaje_padding)

# Imprimir resultados del cifrado
print("El texto cifrado en bytes (hex):", texto_cifrado_bytes.hex())
print("Texto cifrado (Base64):", b64encode(texto_cifrado_bytes).decode('utf-8'))
print("iv (Base64):", b64encode(iv_bytes).decode('utf-8'))





