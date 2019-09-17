from csv import reader
from hashlib import sha256, pbkdf2_hmac
from random import getrandbits

from stuff import attempt_login

COMMON_PASSWORDS_PATH = "common_passwords.txt"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def hash_sha256(x):
    return sha256(x.encode('utf-8')).hexdigest()

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=" ")
        header = next(r)
        assert(header[0] == "username")
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = [line.rstrip('\n') for line in f]
    return pws

def hash_attack(hashed_creds):
    common_pws = load_common_passwords()
    rainbow_mapping = {hash_sha256(pw): pw for pw in common_pws}
    for cred in hashed_creds:
        if cred[1] in rainbow_mapping and \
            attempt_login(cred[0], rainbow_mapping[cred[1]]):
            print(cred)

def brute_force_attack(target_hash, target_salt):
    pass

def main():
    hashed_creds = load_breach(HASHED_BREACH_PATH)
    hash_attack(hashed_creds)
    print("-" * 20)
    salted_creds = load_breach(SALTED_BREACH_PATH)
    brute_force_attack(salted_creds[0][1], salted_creds[0][2])

if __name__ == "__main__":
    main()
