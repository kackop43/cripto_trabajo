# AES/GCM
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Cifrado
textoPlano_que_necesitamos_cifrar_bytes = bytes('He descubierto el error y no volveré a hacerlo mal', 'UTF-8')

# La clave proporcionada en hexadecimal
key = bytes.fromhex('E2CFF885901B3449E9C448BA5B948A8C4EE322152B3F1ACFA0148FB3A426DB74')

# El nonce proporcionado en base64, se decodifica a bytes
nonce = b64decode('9Yccn/f5nJJhAt2S')

# Datos asociados (en este caso vacío)
datos_asociados_bytes = bytes("", "UTF-8")  # --> sin datos asociados

# Crear el cifrador AES en modo GCM
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

# Actualizamos con los datos asociados (aunque no haya datos asociados, se sigue llamando a update)
cipher.update(datos_asociados_bytes)

# Cifrar el texto plano
texto_cifrado_bytes, tag = cipher.encrypt_and_digest(textoPlano_que_necesitamos_cifrar_bytes)

# Convertir a base64
nonce_b64 = b64encode(cipher.nonce).decode('utf-8')
texto_cifrado_b64 = b64encode(texto_cifrado_bytes).decode('utf-8')
tag_b64 = b64encode(tag).decode('utf-8')

# Convertir a hexadecimal
nonce_hex = cipher.nonce.hex()
texto_cifrado_hex = texto_cifrado_bytes.hex()
tag_hex = tag.hex()

# Mostrar los resultados en ambos formatos
print("Texto cifrado en Hexadecimal:", texto_cifrado_hex)
print("Texto cifrado en Base64:", texto_cifrado_b64)
print("Nonce en Hexadecimal:", nonce_hex)
print("Nonce en Base64:", nonce_b64)
print("Tag en Hexadecimal:", tag_hex)
print("Tag en Base64:", tag_b64)


# Para completar, si necesitas almacenar todo en formato JSON:
mensaje_json = json.dumps({
    'nonce': nonce_b64,
    'datos asociados': b64encode(datos_asociados_bytes).decode('utf-8'),
    'tag': tag_b64,
    'texto cifrado': texto_cifrado_b64
})
print("\nMensaje JSON (cifrado):")
print(mensaje_json)

# Descifrado para verificar que el texto cifrado se descifra correctamente
try:
    # Decodificar los datos del mensaje JSON (usando Base64)
    b64 = json.loads(mensaje_json)
    nonce_desc_bytes = b64decode(b64['nonce'])
    texto_cifrado_bytes_desc = b64decode(b64['texto cifrado'])
    tag_desc_bytes = b64decode(b64['tag'])
    datos_asociados_desc_bytes = b64decode(b64['datos asociados'])

    # Crear el descifrador AES en modo GCM con el mismo nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_desc_bytes)
    
    # Actualizar con los mismos datos asociados
    cipher.update(datos_asociados_desc_bytes)
    
    # Descifrar y verificar el texto
    mensaje_desc_bytes = cipher.decrypt_and_verify(texto_cifrado_bytes_desc, tag_desc_bytes)

    # Mostrar el texto descifrado y verificar que coincida con el original
    print("\nTexto descifrado:", mensaje_desc_bytes.decode("utf-8"))

    # Verificar que el texto descifrado es igual al texto original
    if mensaje_desc_bytes == textoPlano_que_necesitamos_cifrar_bytes:
        print("\nEl texto descifrado es correcto y coincide con el texto original (usando Base64).")
    else:
        print("\nEl texto descifrado NO coincide con el texto original (usando Base64).")

    # Ahora verificamos con la representación en Hexadecimal
    # Descifrado usando Hexadecimal
    nonce_desc_bytes = bytes.fromhex(nonce_hex)
    texto_cifrado_bytes_desc = bytes.fromhex(texto_cifrado_hex)
    tag_desc_bytes = bytes.fromhex(tag_hex)

    # Crear el descifrador AES en modo GCM con el mismo nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_desc_bytes)
    
    # Actualizar con los mismos datos asociados
    cipher.update(datos_asociados_desc_bytes)
    
    # Descifrar y verificar el texto
    mensaje_desc_bytes_hex = cipher.decrypt_and_verify(texto_cifrado_bytes_desc, tag_desc_bytes)

    # Mostrar el texto descifrado y verificar que coincida con el original
    print("\nTexto descifrado (Hexadecimal):", mensaje_desc_bytes_hex.decode("utf-8"))

    # Verificar que el texto descifrado es igual al texto original
    if mensaje_desc_bytes_hex == textoPlano_que_necesitamos_cifrar_bytes:
        print("\nEl texto descifrado es correcto y coincide con el texto original (usando Hexadecimal).")
    else:
        print("\nEl texto descifrado NO coincide con el texto original (usando Hexadecimal).")

except (ValueError, KeyError) as error:
    print('Problemas para descifrar....')
    print("El motivo del error es: ", error)
