# -*- coding: utf-8 -*-
"""
Handles hashing and encryption of variables
"""
import argon2
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def hashUserPassword(password):
    hasher = argon2.PasswordHasher()
    hashedMasterPassword = hasher.hash(password)
    return hashedMasterPassword

def verifyUserPassword(hashedPassword, password):
    hasher = argon2.PasswordHasher()
    try:
        hasher.verify(hashedPassword, password)
        print("login success")
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False
    
def makeKey(salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encryptServiceAccessKey(userPassword, serviceAccessPassword):
    userPassword = userPassword.encode()
    salt = os.urandom(16)
    key = makeKey(salt, userPassword)
    f = Fernet(key)
    encryptedAccess = f.encrypt(serviceAccessPassword.encode())
    return encryptedAccess, salt

def decryptServiceAccessKey(userPassword, encryptedAccess, salt):
    userPassword = userPassword.encode()
    key = makeKey(salt, userPassword)
    f = Fernet(key)
    decryptedAccess = f.decrypt(encryptedAccess)
    decryptedAccess.decode()
    return decryptedAccess

def encryptServiceWithKey(key, serviceAttribute):
    f = Fernet(key)
    encryptedService = f.encrypt(serviceAttribute.encode())
    return encryptedService