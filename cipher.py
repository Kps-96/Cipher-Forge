import base64
import hashlib
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# QWERTY Mapping
QWERTY_MAP = {
    1: 'Q', 2: 'W', 3: 'E', 4: 'R', 5: 'T', 6: 'Y', 7: 'U', 8: 'I', 9: 'O', 10: 'P',
    11: 'A', 12: 'S', 13: 'D', 14: 'F', 15: 'G', 16: 'H', 17: 'J', 18: 'K', 19: 'L',
    20: 'Z', 21: 'X', 22: 'C', 23: 'V', 24: 'B', 25: 'N', 26: 'M'
}
REVERSE_QWERTY_MAP = {v: k for k, v in QWERTY_MAP.items()}

# Generate RSA keys
def generate_rsa_keys():
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    return private_key, public_key

# Encrypt AES key using RSA
def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return base64.b64encode(cipher_rsa.encrypt(aes_key)).decode()

# Decrypt AES key using RSA
def decrypt_aes_key(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

# AES Encryption
def aes_encrypt(text, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# AES Decryption
def aes_decrypt(encrypted_text, aes_key):
    data = base64.b64decode(encrypted_text)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# HMAC Generation
def generate_hmac(text, hmac_key):
    return hmac.new(hmac_key, text.encode(), hashlib.sha256).hexdigest()

# Verify HMAC Integrity
def verify_hmac(text, hmac_key, received_hmac):
    return hmac.compare_digest(generate_hmac(text, hmac_key), received_hmac)

# Convert text using ASCII to QWERTY Mapping
def ascii_to_qwerty(text):
    length = len(text)
    transformed_text = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            ascii_val = ord(char.upper()) - 64  # Convert to 1-26 range
            new_val = (ascii_val + length) % 26 or 26  # Apply length shift
            qwerty_char = QWERTY_MAP[new_val]
            transformed_text += qwerty_char if is_upper else qwerty_char.lower()
        else:
            transformed_text += char  # Keep numbers and symbols unchanged
    return transformed_text

# Reverse QWERTY Mapping to ASCII Conversion
def qwerty_to_ascii(text, length):
    reversed_text = ""
    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            qwerty_val = REVERSE_QWERTY_MAP[char.upper()]
            original_val = (qwerty_val - length + 26) % 26 or 26  # Reverse shift
            original_char = chr(original_val + 64)  # Convert back to ASCII letter
            reversed_text += original_char if is_upper else original_char.lower()
        else:
            reversed_text += char  # Keep numbers and symbols unchanged
    return reversed_text

# Convert text to extended ASCII format
def to_extended_ascii(text):
    return "".join(chr((ord(c) % 128) + 128) for c in text)

# Convert extended ASCII back to normal text
def from_extended_ascii(text):
    return "".join(chr((ord(c) - 128) % 128) for c in text)

if __name__ == "__main__":
    # Generate RSA key pair
    private_key, public_key = generate_rsa_keys()

    # Generate AES key and HMAC key
    aes_key = get_random_bytes(32)
    hmac_key = get_random_bytes(32)

    # Encrypt AES key using RSA
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    # Take user input
    plain_text = input("Enter text to encrypt: ")

    # Step 1: ASCII to QWERTY Mapping
    transformed_text = ascii_to_qwerty(plain_text)

    # Step 2: Encrypt using AES
    encrypted_aes_text = aes_encrypt(transformed_text, aes_key)

    # Step 3: Generate HMAC and append to the encrypted text
    message_hmac = generate_hmac(transformed_text, hmac_key)
    final_encrypted_message = f"{encrypted_aes_text}:{message_hmac}"

    # Step 4: Convert to Extended ASCII format
    unreadable_extended_ascii = to_extended_ascii(final_encrypted_message)

    print("\n--- Encrypted Data ---")
    print(f"🔐 Encrypted Text (Extended ASCII): {unreadable_extended_ascii}")
    print(f"🔑 RSA Encrypted AES Key: {encrypted_aes_key}")

    # --- Decryption Process ---
    print("\n--- Decryption Process ---")
    
    # Step 5: Convert extended ASCII back to original encrypted text
    decoded_message = from_extended_ascii(unreadable_extended_ascii)
    encrypted_aes_text, received_hmac = decoded_message.split(":")

    # Step 6: Decrypt AES Key
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

    # Step 7: Decrypt AES Text
    decrypted_qwerty_text = aes_decrypt(encrypted_aes_text, decrypted_aes_key)

    # Step 8: Verify HMAC
    if verify_hmac(decrypted_qwerty_text, hmac_key, received_hmac):
        print("✅ HMAC verified! Message is authentic.")
        final_decrypted_text = qwerty_to_ascii(decrypted_qwerty_text, len(plain_text))
        print(f"🔓 Decrypted Text: {final_decrypted_text}")
    else:
        print("❌ HMAC verification failed! Possible tampering detected.")
