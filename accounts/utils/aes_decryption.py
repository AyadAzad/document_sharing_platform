from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

def decrypt_file(file_path, aes_key, output_path):
    try:
        # Check if the encrypted file exists
        if not os.path.exists(file_path):
            print(f"Error: The encrypted file at {file_path} does not exist.")
            return

        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        # Ensure the key is 16, 24, or 32 bytes long for AES
        aes_key = aes_key.ljust(32, b'\0')  # Padding the key to 32 bytes if it's shorter

        # Extract the IV (first 16 bytes) and encrypted data (remaining bytes)
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]

        # Initialize AES cipher in decryption mode with the extracted IV
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data and remove padding
        decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Write the decrypted data to a file
        with open(output_path, "wb") as output_file:
            output_file.write(unpadded_data)

        print(f"File decrypted and saved to {output_path}")

    except Exception as e:
        print(f"Error during decryption: {e}")
