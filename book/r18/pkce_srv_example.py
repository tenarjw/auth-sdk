import hashlib
import base64

# code_challenge_method == 'S256'
code_verifier_bytes = code_verifier.encode("utf-8")
hash_bytes = hashlib.sha256(code_verifier_bytes).digest()
calculated_challenge = base64.urlsafe_b64encode(hash_bytes).rstrip(b"=").decode()

is_valid = (calculated_challenge == code_challenge)
