import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from django.core.files.base import ContentFile


# AES encryption
def encrypt_file(file, key, original_filename):
    # 1:Generate a random 16-byte IV
    iv = os.urandom(16)

    # 2: Create the AES Cipher in CBC mode with the key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 3:Read the file content from InMemoryUploadedFile
    file_data = file.read()

    # 4:Add padding to make the data length compatible with AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # 5: Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    #  6: Combine IV and encrypted data
    encrypted_file_content = iv + encrypted_data

    # Return the encrypted content with a specified name
    encrypted_filename = f"encrypted_{original_filename}"
    return ContentFile(encrypted_file_content, name=encrypted_filename)
