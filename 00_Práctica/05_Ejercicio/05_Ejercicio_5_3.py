import hashlib

m1 = hashlib.sha3_256() #A nivel de criptografia es buena opcion SHA2
texto_hashear_bytes=bytes("En KeepCoding aprendemos cómo protegernos con criptografía.", "utf8") 
m1.update(texto_hashear_bytes)
print("sha3-256:    " + m1.digest().hex())


