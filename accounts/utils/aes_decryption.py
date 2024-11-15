from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def decrypt_file(file_path, aes_key, output_path):
    with open(file_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    # Initialize AES cipher in decryption mode with the extracted IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=encrypted_data[:16])
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)

    # If the decrypted data is binary, write it to a file
    with open(output_path, "wb") as output_file:
        output_file.write(decrypted_data)

    print(f"File decrypted and saved to {output_path}")
