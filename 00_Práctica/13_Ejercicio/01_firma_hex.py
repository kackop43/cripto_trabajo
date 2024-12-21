from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Mensaje que se desea firmar
mensaje = "El equipo está preparado para seguir con el proceso, necesitaremos más recursos."
mensaje_bytes = mensaje.encode('utf-8')

# Importar la clave privada desde el fichero
with open("clave-rsa-oaep-priv.pem", "r") as file_priv:
    key_private = RSA.import_key(file_priv.read())

# Calcular el hash del mensaje usando SHA-256
hash_mensaje = SHA256.new(mensaje_bytes)

# Generar la firma digital usando PKCS#1 v1.5
firma = pkcs1_15.new(key_private).sign(hash_mensaje)

# Mostrar la firma en formato hexadecimal
print("Firma en hexadecimal:", firma.hex())


