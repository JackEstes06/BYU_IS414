import base64
from pqcrypto.sign import dilithium2 as dilithium

def verify_signature(message, signature, public_key):
    """
    Verifies a signature using the CRYSTAL-Dilithium signature scheme.

    :param message: The original message that was signed (bytes).
    :param signature: The signature to verify (bytes).
    :param public_key: The public key for the signature verification (bytes).
    :return: True if the signature is valid, False otherwise.
    """
    try:
        if isinstance(signature, str):
            signature = base64.b64decode(signature)
        if isinstance(public_key, str):
            public_key = base64.b64decode(public_key)

        # Use the verify method from the pqcrypto library to verify the signature
        is_valid = dilithium.verify(message, signature, public_key)
        return is_valid
    except ValueError:
        # In case of any error, the signature is invalid
        return False

# Example usage
message = b"Hello, this is a test message."
signature = b"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"
public_key = b"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"

if verify_signature(message, signature, public_key):
    print("Signature is valid.")
else:
    print("Signature is invalid.")
