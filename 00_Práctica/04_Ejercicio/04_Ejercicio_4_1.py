#Verificar que algoritmo de firma hemos utilizado (jwt)
import jwt
import json

# El token JWT que queremos verificar
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c3VhcmlvIjoiRG9uIFBlcGl0byBkZSBsb3MgcGFsb3RlcyIsInJvbCI6ImlzTm9ybWFsIiwiaWF0IjoxNjY3OTMzNTMzfQ.gfhw0dDxp6oixMLXXRP97W4TDTrv0y7B5YjD0U8ixrE"

# Clave secreta utilizada para firmar el token
clave_secreta = "Con KeepCoding aprendemos"  # Cambia esto por la clave secreta que se usó al firmar el token

# Función para verificar el algoritmo de firma y explicar por qué se utilizó
def verificar_algoritmo_firma(jwt_token, clave):
    try:
        # Paso 1: Extraemos y analizamos el header
        header = jwt.get_unverified_header(jwt_token)  # Obtiene el header del token sin verificar la firma
        algoritmo = header.get("alg", "No especificado")

        # Explicación del algoritmo según el header
        if algoritmo == "HS256":
            explicacion = (
                "El algoritmo HS256 (HMAC-SHA256) fue utilizado porque es eficiente "
                "y proporciona autenticidad e integridad al combinar una clave secreta "
                "con la función hash SHA-256. Esto asegura que solo alguien con la clave secreta "
                "puede generar o verificar este token."
            )
        elif algoritmo in ["HS384", "HS512"]:
            explicacion = (
                f"El algoritmo {algoritmo} (HMAC con SHA-{algoritmo[-3:]}) fue utilizado para ofrecer "
                "un nivel de seguridad superior al SHA-256, generando hashes más largos. Es útil si la clave "
                "secreta es muy robusta o si se requiere mayor resistencia a ataques criptográficos."
            )
        else:
            explicacion = (
                f"El algoritmo especificado es {algoritmo}, pero no es HS256, HS384 o HS512. "
                "Verifica si este algoritmo es compatible con tu implementación."
            )

        # Paso 2: Verificamos la firma del token
        jwt.decode(jwt_token, clave, algorithms=[algoritmo])  # Verifica la firma y decodifica el token
        firma_valida = "La firma es válida. Esto confirma que el algoritmo fue usado correctamente."
    except jwt.exceptions.InvalidSignatureError:
        firma_valida = "La firma NO es válida. Es posible que la clave secreta no coincida o que el token haya sido modificado."
        explicacion = "No se puede confirmar el algoritmo porque la firma no coincide."
    except Exception as e:
        firma_valida = f"Error al verificar el token: {e}"
        explicacion = "No se pudo determinar el algoritmo debido a un error inesperado."

    return algoritmo, explicacion, firma_valida

# Llamamos a la función para verificar el token
algoritmo, explicacion, firma_valida = verificar_algoritmo_firma(token, clave_secreta)

# Mostramos los resultados
print(f"Algoritmo utilizado en la firma: {algoritmo}")
print(f"Explicación del algoritmo: {explicacion}")
print(f"Estado de la firma: {firma_valida}")
