from hashlib import sha256
from Crypto.Cipher import ChaCha20

# Given parameters
password = "whodrinksroots"
nonce = b"abcdefgh"  # Convert to bytes

# Derive the key using SHA-256
key = sha256(password.encode()).digest()

# Read the encrypted file
with open("PO_encrypted.pdf", "rb") as f:
    encrypted_data = f.read()

# Decrypt using ChaCha20
cipher = ChaCha20.new(key=key, nonce=nonce)
decrypted_data = cipher.decrypt(encrypted_data)

# Save the decrypted file
with open("PO-decrypted.pdf", "wb") as f:
    f.write(decrypted_data)

print("Decryption complete. File saved as PO-decrypted.pdf")