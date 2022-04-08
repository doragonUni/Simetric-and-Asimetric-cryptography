# decifrar p y q, a partir de N
# dado un texto cifrado C, para descrifar necesitamos C^d mod N
# N es público (pk)
# e es público (pk)
# d es privado (sk)
# dado que d se calcula como e-1mod phi(N)
# phi(N) = (p-1)*(q-1)
from pydoc import getpager
import lorem
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization.base import Encoding, PublicFormat, NoEncryption
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1, RSAPrivateNumbers, \
    RSAPublicNumbers

from constants import MILLER_RABIN_ROUNDS
import decimal
import constants
import utils

def getPrimes(N):
    decimal.getcontext().prec = 4096
    x = decimal.Decimal(N)
    sqrtN = x.sqrt()
    sqrtN_int = int(sqrtN)
    q = utils.next_prime(sqrtN_int)
    p = N//q
    return p, q

def deciphered(cipheredDoc, p, q):
    sk = utils.new_fixed_rsa_key(p, q)
    decipheredDoc = sk.decrypt(cipheredDoc, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))
    with open(constants.DECIPHERED_PATH_WITH_CONSECUTIVE_PRIME, 'wb') as f:
        print("Saving deciphered version of text by calculating p and q...")
        f.write(decipheredDoc)

if __name__ == "__main__":
    pk = utils.load_public_key_file(constants.PUBLIC_KEY_PATH)
    N = utils.get_n(pk)
    print("this is the N", N)
    p, q = getPrimes(N)
    with open(constants.CIPHERED_PATH, 'rb') as f:
        C = f.read()
        deciphered(C, p, q) 
    
        
