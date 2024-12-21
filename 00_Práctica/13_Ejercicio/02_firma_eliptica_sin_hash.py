#ED Import
#Tanto creación como comprobación de la clave elíptica
import ed25519

publickey = open("ed25519-publ","rb").read()
privatekey = open("ed25519-priv","rb").read()

signedKey = ed25519.SigningKey(privatekey)
msg = bytes('El equipo está preparado para seguir con el proceso, necesitaremos más recursos.','utf8')

# --------------------------------------------------------------------------------------
#Lo usamos para generar la clave y convertirla a hex
signature = signedKey.sign(msg, encoding = 'hex') 

#Lo usamos para comprobar la clave
#signature = b'bf32592dc235a26e31e231063a1984bb75ffd9dc5550cf30105911ca4560dab52abb40e4f7e2d3af828abac1467d95d668a80395e0a71c51798bd54469b7360d'
# --------------------------------------------------------------------------------------

#Hexadecimal
signature_hexa = signedKey.sign(msg)
signature_hexadecimal = signature_hexa.hex()


print("Firma Generada (64 bytes):", signature)
print("\nFirma Generada (Hexadecimal):", signature_hexadecimal)

try:
    verifyKey = ed25519.VerifyingKey(publickey.hex(),encoding="hex")
    verifyKey.verify(signature, msg, encoding='hex')
    print("\nLa firma es válida")
except:
    print("\nFirma inválida!")
