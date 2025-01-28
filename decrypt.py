def decrypt_text(encrypted_data: str, password: str) -> str:
    # Decode the Base64 string
    combined = base64.urlsafe_b64decode(encrypted_data)
    
    # Extract salt, IV, and ciphertext
    salt = combined[:16]
    iv = combined[16:32]
    ciphertext = combined[32:]
    
    # Derive the key using the same password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

# Example usage:
decrypted = decrypt_text(encrypted, input("What is your M Pass ?"))
print("Decrypted:", decrypted)
