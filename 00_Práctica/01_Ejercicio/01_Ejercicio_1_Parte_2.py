#XOR
# Claves conocidas
clave_fija_1 = "B1EF2ACFE2BAEEFF"  # Clave fija en código
clave_final = "91BA13BA21AABB12"  # Clave final en memoria (desarrollo)
clave_dinamica = "B98A15BA31AEBB3F" # Clave dinámica en producción que se modifica en el fichero de propiedades

# Función para calcular XOR entre dos claves hexadecimales
def calcular_xor(clave1, clave2):

    # Convertimos las claves de hexadecimal a bytes
    bytes1 = bytes.fromhex(clave1)
    bytes2 = bytes.fromhex(clave2)

    # Aplicamos XOR byte a byte
    resultado = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

    # Convertimos el resultado de vuelta a hexadecimal
    return resultado.hex().upper()


# Primera parte: Encontrar la clave en el fichero de propiedades
clave_properties = calcular_xor(clave_fija_1, clave_final)
print(f"Clave fija 2 (desarrollo): {clave_properties}")


# Segunda parte: Clave en memoria en producción 
clave_final_memoria = calcular_xor(clave_fija_1, clave_dinamica)
print(f"Clave final en memoria (producción): {clave_final_memoria}")
