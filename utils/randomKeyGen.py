import random
import os
import hashlib
import hmac
import secrets


def salt_gen(length=16):
    return os.urandom(length)
    

def seed_gen():
    return secrets.token_hex(16)
    

def key_gen(salt,seed,length=32):
    return hmac.new(salt, seed.encode(), hashlib.sha256).digest()[:length]

def gen_encryption_comps():
    salt = salt_gen()
    seed = seed_gen()
    key = key_gen(salt, seed)
    return{
        'Salt': salt.hex(),
        'Seed': seed,
        'Key': key.hex()
    }

def save_key(id):
    filename = f"{id}_key.txt"
    unique_key = False
    
    while not unique_key:
        encrypt_comps = gen_encryption_comps()
        encrypt_key = encrypt_comps['Key']

        if os.path.exists(filename):
            with open(filename, 'r') as file:
                existing_keys = file.readlines()
                existing_keys = [line.strip() for line in existing_keys]

                if encrypt_key in existing_keys:
                    print("Duplicate key found, regenarating...")
                    continue

        with open(filename, "a") as file:
            file.write(f"{encrypt_key}\n")
        print(f"Unique key appended to {filename}")

        print("Salt:", encrypt_comps['Salt'])
        print("Seed:", encrypt_comps['Seed'])
        print("Key:", encrypt_comps['Key'])

        unique_key = True


id = input("User ID: ")
save_key(id)

# I might want to add in a unique ID per key instead of just the key. 
#       - Easier lookups, no issues with deleting and reusing indices
#       - Would have to change unique identifcation logic

# I might also want to add the seed and salt with the key
#       - Depending on wheter I use just the key for encryption or the salt and seed as well
#       - Would have to change unique identifcation logic
#       - Would have to storage method

# I might want to add a password requirement
#       - Would need to add a user/password list to cross-reference
#       - Would add MFA

# I might want to add user lookup either in this file or in another
#       - This way a user can gen keys and retrieve if they would like

