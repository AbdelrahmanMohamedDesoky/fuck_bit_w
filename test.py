from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def encrypt_text(plaintext: str, password: str) -> str:
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    combined = salt + iv + ciphertext
    return base64.urlsafe_b64encode(combined).decode()

def decrypt_text(encrypted_data: str, password: str) -> str:
    combined = base64.urlsafe_b64decode(encrypted_data)
    salt = combined[:16]
    iv = combined[16:32]
    ciphertext = combined[32:]
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=500000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()  # <-- Correct return statement

if __name__ == "__main__":
    mode = input("Choose mode (encrypt/decrypt): ").strip().lower()
    
    if mode == "encrypt":
        text = input("Enter text to encrypt: ")
        password = input("Enter encryption password: ")
        encrypted = encrypt_text(text, password)
        print(f"\nEncrypted text:\n{encrypted}")
        
    elif mode == "decrypt":
        text = input("Enter text to decrypt: ")
        password = input("Enter decryption password: ")
        try:
            decrypted = decrypt_text(text, password)
            print(f"\nDecrypted text:\n{decrypted}")
        except:
            print("Decryption failed! Wrong password or corrupted data.")
            
    else:
        print("Invalid mode! Please choose 'encrypt' or 'decrypt'.")
