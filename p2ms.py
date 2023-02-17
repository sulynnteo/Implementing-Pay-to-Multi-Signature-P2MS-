from sys import argv
from binascii import unhexlify

from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

from config import Config


def import_from_pem(name: str) -> bytes:

    with open(f"{name}.pem", "r") as f:
        return f.read()

def import_from_text(name: str) -> str:

    with open(f"{name}.txt", "r") as f:
        return f.read()

def get_amount_to_pop(item: str) -> int | None:

    if item.startswith("OP_"):
        print(f"{item} is popped from the stack.")
        return int(item.split('_')[1])

    else:
        raise Exception("No opcode found.")

def compare_signature_with_public_key(file_index: int, public_keys: list[str], signatures: list[str]) -> list[int | None]:

    valid_signatures = 0

    for i, signature in enumerate(signatures):
        for j, public_key in enumerate(public_keys):
            hash_object = SHA256.new(Config.message.encode("utf-8"))
            key = DSA.import_key(import_from_pem(f"{Config.pem_directory_name}/{file_index}/{Config.public_key_prefix}-{j}"))
            verifier = DSS.new(key, "deterministic-rfc6979")
            print(f"Verifying key: {public_key}")

            try:
                verifier.verify(hash_object, unhexlify(signature.encode("utf-8")))
                print(f"Signature {i} is able to verify public key {j}.")
                valid_signatures += 1

            except ValueError:
                print(f"Signature {i} is unable to verify public key {j}.")
                continue

            if valid_signatures == Config.M:
                return [1]

    return []

def pop_stack(stack: list[str]) -> tuple[list[str], list[str]]:

    public_keys = []
    signatures = []
    
    # Get the number of public keys
    number_of_keys = get_amount_to_pop(stack.pop())

    # Pop the public keys
    for i in range(number_of_keys):
        public_key = stack.pop()
        print(f"Public key {i} is popped from the stack.")
        public_keys.append(public_key)

    # Get the number of signatures
    number_of_signatures = get_amount_to_pop(stack.pop())

    # Pop the signatures
    for i in range(number_of_signatures):
        signature = stack.pop()
        print(f"Signature {i} is popped from the stack.")
        signatures.append(signature)

    return public_keys, signatures

def push_to_stack(file_index: int) -> list[str]:

    public_keys = import_from_text(f"{Config.public_key_prefix}-{file_index}").split('\n')
    signatures = import_from_text(f"{Config.signature_prefix}-{file_index}").split('\n')
    stack = signatures[1:]
    [print(f"Signature {i} is pushed to the stack") for i in range(len(stack))]

    offset = 0

    for i, public_key in enumerate(public_keys[:-1]):
        stack.append(public_key)

        if public_key.startswith("OP_"):
            print(f"{public_key} is pushed to the stack")
            offset += 1

        else:
            print(f"Public Key {i - offset} is pushed to the stack")

    return stack

def main():

    file_index = parse_args()
    stack = push_to_stack(file_index)
    public_keys, signatures = pop_stack(stack)
    stack = compare_signature_with_public_key(file_index, public_keys, signatures)

    print("Transaction is valid.") if stack[0] == 1 else print("Transaction is invalid.")

def parse_args() -> int:

    try:
        return int(argv[1])

    except IndexError:
        print("Please provide a file index to compare.")
        raise

if __name__ == "__main__":
    main()