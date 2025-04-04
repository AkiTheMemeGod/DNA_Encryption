import os
import json
import base64
import tqdm
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load config
CONFIG_FILE = "config.json"


def load_config():
    if not os.path.exists(CONFIG_FILE):
        default_config = {
            "aes_key_length": 256,
            "compression": True,
            "obfuscation": "xor",
            "error_correction": "medium"
        }
        with open(CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=4)
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)


config = load_config()

# Logging setup
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


# AES Encryption
def generate_aes_key():
    return os.urandom(32)  # 256-bit key


def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + b" " * (16 - len(data) % 16)  # PKCS7 Padding
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_aes(encrypted_data, key):
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data.strip()


DNA_MAPPING = {"00": "A", "01": "T", "10": "C", "11": "G"}
REV_DNA_MAPPING = {v: k for k, v in DNA_MAPPING.items()}


def binary_to_dna(binary_data):
    binary_str = "".join(format(byte, "08b") for byte in binary_data)
    dna_sequence = "".join(DNA_MAPPING[binary_str[i:i + 2]] for i in range(0, len(binary_str), 2))
    return dna_sequence
x = [[1,7],[2,6],[3,5],[4,4],[5,4],[6,3],[7,2],[8,1]]

def dna_to_binary(dna_sequence):
    binary_str = "".join(REV_DNA_MAPPING[char] for char in dna_sequence)
    byte_data = bytes(int(binary_str[i:i + 8], 2) for i in range(0, len(binary_str), 8))
    return byte_data


# Encryption process
def encrypt_file(input_file, output_file, key):
    logging.info("Starting encryption...")
    with open(input_file, "rb") as f:
        data = f.read()
    encrypted_data = encrypt_aes(data, key)
    dna_sequence = binary_to_dna(encrypted_data)
    with open(output_file, "w") as f:
        f.write(dna_sequence)
    logging.info("Encryption complete. Output saved to %s", output_file)


# Decryption process
def decrypt_file(input_file, output_file, key):
    logging.info("Starting decryption...")
    with open(input_file, "r") as f:
        dna_sequence = f.read()
    binary_data = dna_to_binary(dna_sequence)
    decrypted_data = decrypt_aes(binary_data, key)
    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    logging.info("Decryption complete. Output saved to %s", output_file)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DNA-based Encryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Mode: encrypt or decrypt")
    parser.add_argument("input", help="Input file")
    parser.add_argument("output", help="Output file")
    args = parser.parse_args()

    aes_key = generate_aes_key()  # In real use, securely store and retrieve keys
    if args.mode == "encrypt":
        encrypt_file(args.input, args.output, aes_key)
    else:
        decrypt_file(args.input, args.output, aes_key)
