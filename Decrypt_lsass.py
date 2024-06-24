import sys
from pathlib import Path

XOR_KEY = b"K4rm4ishere"

def xor_decrypt(data, key):
    key_len = len(key)
    return bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

def main(encrypted_dump_path):
    encrypted_dump_path = Path(encrypted_dump_path)
    decrypted_dump_path = encrypted_dump_path.with_suffix('.decrypted.dmp')

    # Leer el archivo encriptado
    with open(encrypted_dump_path, 'rb') as f:
        encrypted_data = f.read()

    # Verificar que se leyó el archivo
    if not encrypted_data:
        print(f"Error: no se pudo leer el archivo encriptado {encrypted_dump_path}")
        return

    # Desencriptar los datos
    decrypted_data = xor_decrypt(encrypted_data, XOR_KEY)

    # Guardar los datos desencriptados
    with open(decrypted_dump_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Archivo desencriptado guardado como: {decrypted_dump_path}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} <ruta del volcado encriptado>")
        sys.exit(1)

    main(sys.argv[1])
