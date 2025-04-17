from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
import os

class CryptoManager:
    def generate_voter_keys(self):
        key = ECC.generate(curve='secp521r1')  # Must match CRYPTO["ecc_curve"] in config.py
        return {
            'private': key.export_key(format='PEM'),
            'public': key.public_key().export_key(format='PEM')
        }

    def encrypt_vote(self, vote: str, public_key: str) -> tuple:
        # Generate ephemeral ECC key pair for ECDH
        ecc_key = ECC.generate(curve='secp521r1')
        peer_key = ECC.import_key(public_key)
    
        # Perform ECDH key exchange
        shared_secret = ecc_key.d * peer_key.pointQ
    
        # Derive AES key using HKDF
        aes_key = HKDF(shared_secret.x.to_bytes(66, 'big'), 32, b'', SHA512)
    
        # Encrypt vote with AES-GCM
        iv = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(vote.encode())
    
        return (
            iv,
            ciphertext,
            tag,
            ecc_key.public_key().export_key(format='PEM')  # Include ephemeral public key
         )

    def decrypt_vote(self, data: tuple, private_key: str) -> str:
        iv, ciphertext, tag, ephemeral_pub_key = data
        ecc_key = ECC.import_key(private_key)
        peer_key = ECC.import_key(ephemeral_pub_key)
    
        # Perform ECDH key exchange
        shared_secret = ecc_key.d * peer_key.pointQ
    
        # Derive AES key
        aes_key = HKDF(shared_secret.x.to_bytes(66, 'big'), 32, b'', SHA512)
    
        # Decrypt vote
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()

    def sign_data(self, data: bytes, private_key: str) -> bytes:
        key = ECC.import_key(private_key)
        h = SHA512.new(data)
        signer = DSS.new(key, 'fips-186-3')
        return signer.sign(h)

    def verify_signature(self, data: bytes, signature: bytes, public_key: str) -> bool:
        key = ECC.import_key(public_key)
        h = SHA512.new(data)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def generate_hmac(self, data: bytes, key: bytes) -> bytes:
        return HMAC.new(key, data, SHA256).digest()

    def hash_password(self, password: str) -> tuple:
        salt = os.urandom(16)
        hashed_pwd = PBKDF2(password, salt, dkLen=32, count=1000000)
        return (hashed_pwd.hex(), salt.hex())

    def verify_password(self, password: str, hashed_pwd: str, salt: str) -> bool:
        new_hash = PBKDF2(password, bytes.fromhex(salt), dkLen=32, count=1000000)
        return new_hash.hex() == hashed_pwd