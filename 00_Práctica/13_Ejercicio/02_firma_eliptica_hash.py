# ED Import
# Tanto creación como comprobación de la clave elíptica con hash
import ed25519
import hashlib

publickey = open("ed25519-publ", "rb").read()
privatekey = open("ed25519-priv", "rb").read()

signedKey = ed25519.SigningKey(privatekey)
msg = bytes('El equipo está preparado para seguir con el proceso, necesitaremos más recursos.', 'utf8')


# Realizamos un hash del mensaje antes de firmarlo
msg_hash = hashlib.sha512(msg).digest()

# --------------------------------------------------------------------------------------
# Generar la firma utilizando el hash del mensaje
signature = signedKey.sign(msg_hash, encoding='hex') 

# Comprobar la firma
#signature = b'cfa44c31375c4725fcea8e4bd45599eeeecdc41dea219566d412e0f5b9cc65694458d3c0bd9cf25e07de9f7b0137f89ab15592ec5310572205f7ec678c09e700'
# --------------------------------------------------------------------------------------

# Convertir la firma a formato hexadecimal
signature_hexa = signedKey.sign(msg_hash)
signature_hexadecimal = signature_hexa.hex()

print("Firma Generada (64 bytes):", signature)
print("\nFirma Generada (Hexadecimal):", signature_hexadecimal)

try:
    # Crear la clave de verificación usando la clave pública en formato hexadecimal
    verifyKey = ed25519.VerifyingKey(publickey.hex(), encoding="hex")
    # Verificar la firma utilizando el hash del mensaje original
    verifyKey.verify(signature, msg_hash, encoding='hex')
    print("\nLa firma es válida")
except Exception as e:
    print("\nFirma inválida!", str(e))
