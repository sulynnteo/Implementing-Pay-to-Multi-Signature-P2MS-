from binascii import hexlify
from os import makedirs
from os.path import exists

from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

from config import Config


class KeyGenerator:

    def __init__(self):

        self.pem_directory_name = self.get_pem_directory_name(Config.pem_directory_name)

    def get_pem_directory_name(self, name: str) -> str:

        directory_path = f"{name}/%s"
        i = 0

        while exists(directory_path % i):
            i += 1

        directory_path %= i
        makedirs(directory_path)

        return directory_path

    def export_to_pem(self, name: str, data: str):
        file_name = f"{name}-%s.pem"
        file_path = lambda file_name: f"{self.pem_directory_name}/{file_name}"
        i = 0

        while exists(file_path(file_name % i)):
            i += 1

        self.export_to_file(file_path(file_name % i), data)

    def export_to_text(self, name: str, data: str):
        file_name = f"{name}-%s.txt"
        i = 0
        while exists(file_name % i):
            i += 1
        self.export_to_file(file_name % i, data)

    def export_to_file(self, file_name: str, data: str):
        with open(file_name, "w") as f:
            f.write(data)

    def generate_signatures(self, key_objects: list, message: str):
        hash_object = SHA256.new(message.encode("utf-8"))
        signature_bytes = [hexlify(DSS.new(key, "deterministic-rfc6979").sign(hash_object)) for key in key_objects]
        signatures = '\n'.join(signature.decode("utf-8") for signature in signature_bytes)
        self.export_to_text(Config.signature_prefix, f"OP_1\n{signatures}")

    def generate_public_keys(self, M: int, N: int) -> list:

        key_objects = []
        public_keys = []
        M = f"OP_{M}"
        N = f"OP_{N}"
        domain = DSA.generate(2048).domain() # Generate a FIPS 186-4 compliant 2048-bit domain

        for i in range(4):
            key = DSA.generate(2048, domain=domain)
            key_objects.append(key)
            self.export_to_pem(Config.public_key_prefix, key.publickey().export_key("PEM").decode("utf-8"))

            public_key = ''.join(line for line in key.publickey().export_key().decode("utf-8").split('\n')[1:-1])
            public_keys.append(hexlify(public_key.encode("utf-8")).decode("utf-8"))

        public_key_formatted = '\n'.join(public_keys)
        self.export_to_text(Config.public_key_prefix, f"{M}\n{public_key_formatted}\n{N}\nOP_CHECKMULTISIG")

        return key_objects

def main():

    M = Config.M
    N = Config.N
    message = Config.message

    key_generator = KeyGenerator()
    key_objects = key_generator.generate_public_keys(M, N)
    key_generator.generate_signatures(key_objects[:M], message)

if __name__ == "__main__":
    main()