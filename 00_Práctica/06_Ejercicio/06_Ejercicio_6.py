#Calculamos HMAC-256 y verificamos resultado
from Crypto.Hash import HMAC, SHA256

#Introducir clave HMAC
clave_bytes = bytes.fromhex('A212A51C997E14B4DF08D55967641B0677CA31E049E672A4B06861AA4D5826EB')

#Introducir texto
datos = bytes("Siempre existe más de una forma de hacerlo, y más de una solución válida.", "utf8")


def getHMAC(key_bytes,data_bytes):
    hmac256 = HMAC.new(key_bytes, msg=data_bytes, digestmod=SHA256)
    return hmac256.hexdigest()

def validateHMAC(key_bytes,data_bytes,hmac):
    hmac256 = HMAC.new(key_bytes,msg=data_bytes,digestmod=SHA256)
    result = "KO"
    try:
        hmac256.hexverify(hmac)
        result = "OK"
    except ValueError:
        result = "KO"
    print("result: " + result)
    return result


hmac = getHMAC(clave_bytes,datos)

print(hmac)

print(validateHMAC(clave_bytes, datos,hmac))