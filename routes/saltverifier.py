import os
import hashlib

#SRP6 authentication. Client proves it knows password but never sends.
#Server stores a value called verifier created by password(SRP math) and a salt.
#Salt = ramdomly generated 32 byte sequence, mixed into the password before hashing.

def sha1_binary(data: bytes) -> bytes: #Compute SHA1 hash of data (hashlib) and return it as binary bytes (digest).
    return hashlib.sha1(data).digest() 

def int_to_le_bytes(value: int, length: int) -> bytes: #Converts Python integer into byte array, little-endian (less important first) order.
    return value.to_bytes(length, byteorder='little')

def le_bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def generate_srp6_verifier(username: str, password: str):
    username = username.upper()
    password = password.upper()

    salt = os.urandom(32)

    h1 = sha1_binary(f"{username}:{password}".encode()) #.encode = string to byte
    h2 = sha1_binary(salt + h1)  #salted and double hashed

    h2_int = le_bytes_to_int(h2)

    G = 7
    N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB8", 16)

    verifier_int = pow(G, h2_int, N) #verifier_int = (G ^ h2_int) mod N

    verifier = int_to_le_bytes(verifier_int, 32)

    return salt, verifier



#The verifier in SRP6 is a large number computed with modular math. 
#AzerothCore stores it as a 32-byte binary blob, in little-endian format.
#https://www.azerothcore.org/wiki/account
