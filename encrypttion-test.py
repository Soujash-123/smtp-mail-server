from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

# AES encryption and decryption functions
def encrypt_message(message):
    # Generate a random 32-byte key for AES-256
    key = os.urandom(32)
    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Pad the message to make it a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Initialize the cipher for AES encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return the key, IV, and encrypted data
    return key, iv, encrypted_data

def decrypt_message(encrypted_data, key, iv):
    # Initialize the cipher for AES decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding after decryption
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Main function to run the program
def main():
    message = input("Enter the string to encrypt: ")

    # Encrypt the message
    key, iv, encrypted = encrypt_message(message)

    # Encode key and encrypted message to base64 for easier display
    b64_key = base64.b64encode(key).decode('utf-8')
    b64_iv = base64.b64encode(iv).decode('utf-8')
    b64_encrypted = base64.b64encode(encrypted).decode('utf-8')

    print("Generated Key (Base64):", b64_key)
    print("IV (Base64):", b64_iv)
    print("Encrypted Message (Base64):", b64_encrypted)

    # Decrypt the message to verify
    decrypted = decrypt_message(encrypted, key, iv)
    print("Decrypted Message:", decrypted)

if __name__ == "__main__":
    main()
