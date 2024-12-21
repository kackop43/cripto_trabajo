#Verificación e intencón del hacker al cambiar el token
import jwt
from jwt.exceptions import InvalidSignatureError, DecodeError

# Token proporcionado por el hacker. Este token tiene un payload que intenta establecer privilegios de administrador.
token_hacker = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJ1c3VhcmlvIjoiRG9uIFBlcGl0byBkZSBsb3MgcGFsb3RlcyIsInJvbCI6ImlzQWRtaW4iLCJpYXQiOjE2Njc5MzM1MzN9."
    "krgBkzCBQ5WZ8JnZHuRvmnAZdg4ZMeRNv2CIAODlHRI"
)

# Clave secreta legítima que el servidor usaría para validar los tokens. Sin esta clave, el token no puede ser validado correctamente.
clave_secreta_legitima = "clave_secreta_legitima"

def analizar_token(token, clave_secreta):
    """
    Intenta validar el token usando la clave secreta legítima.
    Si la firma no coincide, se lanza un error, lo que indica que el token ha sido manipulado o generado con una clave incorrecta.
    """
    try:
        # Decodificar el token y verificar la firma
        payload = jwt.decode(token, clave_secreta, algorithms=["HS256"])
        print(f"\u2705 Token válido. Payload: {payload}")
    except InvalidSignatureError:
        # Esto ocurre si la firma del token no coincide con la clave secreta
        print("\u26a0\ufe0f La firma del token no es válida. Es posible que el hacker haya manipulado el token o usado una clave secreta incorrecta.")
    except DecodeError:
        # Esto ocurre si el token está mal formado
        print("\u26a0\ufe0f El token está mal formado o ha sido manipulado.")
    except Exception as e:
        # Captura otros errores inesperados
        print(f"\u26a0\ufe0f Error inesperado al validar el token: {e}")

def analizar_intenciones(token):
    """
    Extrae y analiza el contenido del token (header y payload) sin verificar la firma.
    Esto permite entender lo que el hacker está intentando lograr.
    """
    try:
        # Extraer el header sin verificar la firma
        header = jwt.get_unverified_header(token)
        # Decodificar el payload sin verificar la firma
        payload = jwt.decode(token, options={"verify_signature": False})

        print("\u2699\ufe0f Análisis del token:")
        print(f"Header: {header}")
        print(f"Payload: {payload}")

        # Analizar posibles intenciones maliciosas en el payload
        if payload.get("rol") == "isAdmin":
            print("\u26a0\ufe0f El hacker está intentando obtener privilegios de administrador.")
        else:
            print("El token no parece tener intenciones sospechosas en el rol.")
    except Exception as e:
        # Captura errores al intentar analizar el token
        print(f"\u26a0\ufe0f Error al analizar el token: {e}")

# Paso 1: Analizar las intenciones del hacker
print("1\ufe0f\u20e3 Analizando el intento del hacker...")
analizar_intenciones(token_hacker)

# Paso 2: Intentar validar el token con la clave legítima
print("\n2\ufe0f\u20e3 Intentando validar el token con la clave legítima...")
analizar_token(token_hacker, clave_secreta_legitima)
print("")