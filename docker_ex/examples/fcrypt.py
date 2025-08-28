from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.hashes as hashes

def encrypt_data(rsa_public_key, input_data):
    """Szyfruje dane za pomocą AES-GCM i zabezpiecza klucz RSA."""
    key = urandom(32)  # Klucz AES-256
    iv = urandom(12)   # IV dla GCM (12 bajtów)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    
    # Dodanie metadanych do uwierzytelnienia (np. kontekst pliku)
    encryptor.authenticate_additional_data(b"metadata")
    
    encrypted = encryptor.update(input_data) + encryptor.finalize()
    # Dołącz IV, klucz i tag uwierzytelnienia do szyfrowania RSA
    encrypted_key = rsa_public_key.encrypt(
        iv + key + encryptor.tag,  # IV (12) + klucz (32) + tag (16)
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    return (encrypted_key, encrypted)

def decrypt_data(rsa_private_key, encrypted_key, encrypted_data):
    """Odszyfruje dane za pomocą klucza RSA i AES-GCM."""
    iv_key_tag = rsa_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )
    iv = iv_key_tag[:12]         # Pierwsze 12 bajtów to IV
    key = iv_key_tag[12:44]      # Następne 32 bajty to klucz
    tag = iv_key_tag[44:]        # Ostatnie 16 bajtów to tag GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    
    # Weryfikacja metadanych
    decryptor.authenticate_additional_data(b"metadata")
    
    return decryptor.update(encrypted_data) + decryptor.finalize()
