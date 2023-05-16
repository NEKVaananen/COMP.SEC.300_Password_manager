# -*- coding: utf-8 -*-
"""
Module that handles hashing and encryption functions
"""
import argon2
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

"""
Function that uses argon2 to hash a plaintext password.
Returns the hashed password. Used when registering and logging in.
Additionally called everytime user authenticates to calculate new hash.
"""
def hashUserPassword(password):
    hasher = argon2.PasswordHasher()
    hashedMasterPassword = hasher.hash(password)
    return hashedMasterPassword

"""
Function that uses argon2 to verify if a plaintext password corresponds to
the hashed password. Used whrn logging in.
"""
def verifyUserPassword(hashedPassword, password):
    hasher = argon2.PasswordHasher()
    try:
        hasher.verify(hashedPassword, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

"""
Function that uses PBKDF2 to cnstruct a key for Fernet. Used to construct a new
key for encryption or reconstruct a key for decryption.
Returns the key.
"""
def makeKey(salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

"""
Function used to encrypt the access password. 
returns the encrypted access password and the salt used to encrypt it.
"""
def encryptServiceAccessKey(userPassword, serviceAccessPassword):
    userPassword = userPassword.encode()
    salt = os.urandom(16)
    key = makeKey(salt, userPassword)
    f = Fernet(key)
    encryptedAccess = f.encrypt(serviceAccessPassword.encode())
    return encryptedAccess, salt

"""
Function used to decrypt the access password. 
returns the decrypted access password.
"""
def decryptServiceAccessKey(userPassword, encryptedAccess, salt):
    userPassword = userPassword.encode()
    key = makeKey(salt, userPassword)
    f = Fernet(key)
    decryptedAccess = f.decrypt(encryptedAccess)
    decryptedAccess.decode()
    return decryptedAccess

"""
Function used to encrypt service credentials using a key. For service credentials the key has to
be contructed separately for every service. The key is constructed using makeKey function.
Returns the encryted service credential.
"""
def encryptServiceWithKey(key, serviceAttribute):
    f = Fernet(key)
    encryptedService = f.encrypt(serviceAttribute.encode())
    return encryptedService