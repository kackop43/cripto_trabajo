#Chacha20
from Crypto.Cipher import ChaCha20_Poly1305
from base64 import b64decode, b64encode
from Crypto.Random import get_random_bytes
import json

try:

    textoPlano_bytes = bytes('KeepCoding te enseña a codificar y a cifrar', 'UTF-8')
    clave = bytes.fromhex('AF9DF30474898787A45605CCB9B936D33B780D03CABC81719D52383480DC3120') #Clave hcifrado-sim-chacha20-256 del keyStore

    #Importante NUNCA debe fijarse el nonce
    #nonce_mensaje = get_random_bytes(12)
    nonce_mensaje = b64decode("9Yccn/f5nJJhAt2S") #Convertimos el nonce a bytes

    #Con la clave y con el nonce se cifra. El nonce debe ser único por mensaje
    #Hoy decido que no tenga datos asociados
    datos_asociados = bytes('', 'utf-8')

    cipher = ChaCha20_Poly1305.new(key=clave, nonce=nonce_mensaje)
    #Por ser cifrado autenticado hacemos un update (lo mismo ocurria en AES-GCM)
    cipher.update(datos_asociados)
    texto_cifrado, tag = cipher.encrypt_and_digest(textoPlano_bytes)
    print("nonce:", b64encode(nonce_mensaje).decode())
    print("Encrypt Text:", b64encode(texto_cifrado).decode())
    print("Datos asociados:", b64encode(datos_asociados).decode())
    print("Tag:", b64encode(tag).decode())

#     #Simulamos el mensaje que se debe enviar, en este caso lo enviaremos todo el contenido en base64
#     mensaje_enviado = { "nonce": b64encode(nonce_mensaje).decode(),"datos asociados": b64encode(datos_asociados).decode(), "texto cifrado": b64encode(texto_cifrado).decode(), "tag": b64encode(tag).decode()}
#     json_mensaje = json.dumps(mensaje_enviado)
#     print("Mensaje: ", json_mensaje)


#     #Descifrado...

    #texto_cifrado_fake=b64decode("gg0khgWfd9GBF9oKY+h/EpRKJ2FzO1Y5vnS0vA==")
    decipher = ChaCha20_Poly1305.new(key=clave, nonce=nonce_mensaje)
    datos_asociados_fake = bytes("pringado","utf-8")
    decipher.update(datos_asociados)
    #decipher.update(datos_asociados_fake)
    plaintext = decipher.decrypt_and_verify(texto_cifrado,tag)
    #plaintext = decipher.decrypt_and_verify(texto_cifrado_fake,tag)
    print('Datos cifrados en claro = ',plaintext.decode('utf-8'))
except (ValueError, KeyError) as error: 
     print("Problemas al descifrar....")
     print("El motivo del error es: ", error)