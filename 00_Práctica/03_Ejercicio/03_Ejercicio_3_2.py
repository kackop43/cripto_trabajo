# Chacha20-Poly1305
from Crypto.Cipher import ChaCha20_Poly1305
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes
import json

try:
    # Texto en claro y clave de cifrado
    textoPlano_bytes = bytes('KeepCoding te enseña a codificar y a cifrar', 'UTF-8')
    clave = bytes.fromhex('AF9DF30474898787A45605CCB9B936D33B780D03CABC81719D52383480DC3120')  # Clave de cifrado (256 bits)

    # Generar un nonce aleatorio (debe ser único por mensaje)
    nonce_mensaje = get_random_bytes(12)  # Generamos un nonce único de 12 bytes

    # Datos asociados (Ayudan a autentificar la integridad)
    datos_asociados = bytes('identificador=12345;usuario=pepito;timestamp=2025-01-03', 'utf-8')  # Ejemplo de datos asociados

    # Cifrado del mensaje con ChaCha20-Poly1305
    cipher = ChaCha20_Poly1305.new(key=clave, nonce=nonce_mensaje)
    cipher.update(datos_asociados)  # Asociamos los datos adicionales
    texto_cifrado, tag = cipher.encrypt_and_digest(textoPlano_bytes)  # Texto cifrado + tag de autenticación

    # Imprimir los datos cifrados en Base64 para facilidad de transmisión
    print("Nonce:", b64encode(nonce_mensaje).decode())  # Codificamos el nonce en Base64
    print("Texto cifrado:", b64encode(texto_cifrado).decode())  # Codificamos el texto cifrado en Base64
    print("Datos asociados:", b64encode(datos_asociados).decode())  # Datos asociados en Base64
    print("Tag:", b64encode(tag).decode())  # Tag en Base64 para la verificación

    # Simulación de envío del mensaje (se enviarán todos los datos en Base64)
    mensaje_enviado = {
        "nonce": b64encode(nonce_mensaje).decode(),
        "datos_asociados": b64encode(datos_asociados).decode(),
        "texto_cifrado": b64encode(texto_cifrado).decode(),
        "tag": b64encode(tag).decode()
    }

    print("Mensaje enviado:", json.dumps(mensaje_enviado, indent=4))  # El "indent=4" hace que el mensaje en JSON sea más legible

    # Descifrado del mensaje recibido
    nonce_recibido = b64decode(mensaje_enviado["nonce"])  # Decodificamos el nonce desde Base64
    datos_asociados_recibidos = b64decode(mensaje_enviado["datos_asociados"])  # Decodificamos los datos asociados
    texto_cifrado_recibido = b64decode(mensaje_enviado["texto_cifrado"])  # Decodificamos el texto cifrado
    tag_recibido = b64decode(mensaje_enviado["tag"])  # Decodificamos el tag

    # Descifrar y verificar la integridad del mensaje
    decipher = ChaCha20_Poly1305.new(key=clave, nonce=nonce_recibido)
    decipher.update(datos_asociados_recibidos)  # Verificamos los datos asociados también

    # Intentamos descifrar y verificar los datos
    plaintext = decipher.decrypt_and_verify(texto_cifrado_recibido, tag_recibido)

    # Si no se lanza ninguna excepción, la verificación fue exitosa
    print('Texto descifrado:', plaintext.decode('utf-8'))

except (ValueError, KeyError) as error:
    print("Problemas al descifrar...")
    print("El motivo del error es:", error)
