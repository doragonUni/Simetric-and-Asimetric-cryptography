import lorem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import constants
import utils

if __name__ == "__main__":
    print("Creating a random document...")
    # creating a new 2048 bit rsa key
    print("Creating a new 2048 bit RSA key...")
    rsakey = utils.new_rsa_key(2048)
    print("Creating a random latin-like sentence...")
    doc = lorem.sentence()
    print("Encrypting sentence...")
    cipheredDoc = rsakey.public_key().encrypt(doc.encode(), padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    decipheredDoc = rsakey.decrypt(cipheredDoc, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    with open(constants.PLAINTEXT_PATH, 'w') as f:
        print("Saving plain text version of text...")
        f.write(doc)
    with open(constants.CIPHERED_PATH, 'wb') as f:
        print("Saving ciphered version of text...")
        f.write(cipheredDoc)
    with open(constants.DECIPHERED_PATH, 'wb') as f:
        print("Saving deciphered version of text...")
        f.write(decipheredDoc)
    print("Done!")
