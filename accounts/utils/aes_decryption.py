# utils/aes_decryption.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

def decrypt_file(encrypted_file_content, aes_key):
    """
    Decrypt an AES-encrypted file using the provided AES key.

    :param encrypted_file_content: Content of the file (including IV) to decrypt
    :param aes_key: Decrypted AES key for decryption
    :return: Decrypted original file content
    """
    # Ensure AES key length matches expected key size (e.g., 32 bytes for AES-256)
    assert len(aes_key) in [16, 24, 32], "Invalid AES key length."

    # Extract the IV from the first 16 bytes of the encrypted file content
    iv = encrypted_file_content[:16]
    encrypted_data = encrypted_file_content[16:]

    # Create AES cipher in CBC mode with the provided AES key and IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding to retrieve the original data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()

    return original_data
