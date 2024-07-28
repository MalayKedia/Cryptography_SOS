import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Step 1: Hash the file using SHA-256
def sha256_hash_file(file_path):
    sha256_hash = hashlib.sha256()

    # Reading the file in chunks to avoid memory overload for large files
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)

    return sha256_hash.digest()  # Return the binary hash value

# Step 2: Generate RSA keys (private and public)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    return private_key, public_key

# Step 3: Sign the hash with the private RSA key
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Step 4: Verify the signature with the public RSA key
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Step 5: Save keys to PEM format (optional)
def save_private_key(private_key, file_name):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(file_name, 'wb') as f:
        f.write(pem)

def save_public_key(public_key, file_name):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(file_name, 'wb') as f:
        f.write(pem)

# Step 6: Load keys from PEM files (optional)
def load_private_key(file_name):
    with open(file_name, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(file_name):
    with open(file_name, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Main example usage
if __name__ == '__main__':
    file_path = 'example.txt'  # Path to the file you want to hash

    # Generate RSA keys
    private_key, public_key = generate_rsa_keys()

    # Hash the file using SHA-256
    file_hash = sha256_hash_file(file_path)
    print(f"SHA-256 Hash of the file: {file_hash.hex()}")

    # Sign the hash using the RSA private key
    signature = sign_data(private_key, file_hash)
    print(f"Signature: {signature.hex()}")

    # Verify the signature using the RSA public key
    verification_result = verify_signature(public_key, file_hash, signature)
    print(f"Signature verification result: {verification_result}")

    # Optional: Save and load keys from files
    save_private_key(private_key, 'private_key.pem')
    save_public_key(public_key, 'public_key.pem')

    # Load keys from files and verify again
    loaded_private_key = load_private_key('private_key.pem')
    loaded_public_key = load_public_key('public_key.pem')

    # Re-verify using loaded public key
    verification_result = verify_signature(loaded_public_key, file_hash, signature)
    print(f"Verification with loaded keys: {verification_result}")
