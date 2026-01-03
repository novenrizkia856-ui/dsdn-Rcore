# generate_keypair.py
# generate Ed25519 keypair + DSDN address (SHA3-512(pubkey)[:20])
# FULLY COMPATIBLE WITH crypto.rs

import hashlib
import nacl.signing
import binascii

def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def derive_address(pubkey: bytes) -> str:
    h = sha3_512(pubkey)
    return binascii.hexlify(h[:20]).decode()

def main():
    # generate Ed25519 keypair
    kp = nacl.signing.SigningKey.generate()
    private_key = kp._seed                     # 32 bytes Ed25519 secret
    public_key = kp.verify_key.encode()        # 32 bytes Ed25519 pubkey

    addr = derive_address(public_key)

    print("=== DSDN KeyPair Generated ===")
    print(f"Private Key (hex 32 bytes): {binascii.hexlify(private_key).decode()}")
    print(f"Public Key  (hex 32 bytes): {binascii.hexlify(public_key).decode()}")
    print(f"Address (20 bytes hex)    : {addr}")
    print("================================")

if __name__ == "__main__":
    main()
