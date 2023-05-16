# -*- coding: utf-8 -*-
"""
Module that handles database interaction
"""

import secrets
import sqlite3
import os
from encryptionHandler import hashUserPassword, verifyUserPassword, encryptServiceAccessKey, decryptServiceAccessKey, makeKey, encryptServiceWithKey

"""
Custom exception for a case where user tries to save duplicate credentials
"""
class serviceExistsException(Exception):
    "user has already saved credentials for this service"
    pass

"""
Class used to connect to the database file. Creates the file if it does not exist
in the filepath.
"""
def connectToDatabase():
    connection = sqlite3.connect('passwords.db')
    cursor = connection.cursor()
    return connection, cursor

"""
Function that generates a cryptographically safe 32 characters long password
"""
def generateRandomPassword():
    password_length = 32
    randomPassword = secrets.token_urlsafe(password_length)
    return randomPassword

"""
Creates tables in the database called passwords, where we store user and their
service credentials.
"""
def createDatabase():
    if not os.path.exists("passwords.db"):
        connection, cursor = connectToDatabase()
        cursor.execute("""CREATE TABLE users (
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                access_key TEXT NOT NULL,
                salt TEXT NOT NULL,
                user_id INTEGER PRIMARY KEY AUTOINCREMENT);""")
        
        cursor.execute("""CREATE TABLE passwords (
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                user_id INT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id));""")
        
        connection.commit()
        connection.close()     

"""
Function that gets users username and password in plaintext. The password is hashed
using argon2. A cryptographically strong password is generated for the purpose of
decrypting the service credentials is then generated. This password symmetrically encrypted
using users master password and random salt with PBKDF2 to generate the Fernet key. We then store the username, 
hashed password, the encrypted access password and its salt to the table. This is used when 
registering. Return true if new user was succesfully registered. False is returned if 
username was already taken by another user.
 OWASP password storage cheat sheet.
"""
def storeNewUser(username, password):
    connection, cursor = connectToDatabase()
    # Check if an user already exists
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    #if user does not exist
    if result is None:
        #Hash users master password and generate password to passwords table
        hashedPassword = hashUserPassword(password)
        accessPassword = generateRandomPassword()
        #encrypt service table password with users password
        encryptedAccess, salt = encryptServiceAccessKey(password, accessPassword)
        
        #store new user and close connection
        cursor.execute("INSERT INTO users (username, password, access_key, salt) VALUES (?, ?, ?, ?)",
                       (username, hashedPassword, encryptedAccess, salt))
        connection.commit()
        connection.close()
        return True
    #user exists
    else:
        #username is already taken!
        connection.close()
        return False

"""
Function used for changing users master password. New password is hashed using argon2, 
the new password is used to generate new PBKDF2 key for fernet encryption. Access password is
then encrypted again using the new key. We then update the users table with the new
hashed password, encrypted access password and the new salt. 
 OWASP password storage cheat sheet.
"""
def updateUserPassword(user_id, password, accessPassword):
    connection, cursor = connectToDatabase()
    try:
        newHashedPassword = hashUserPassword(password)
        encryptedAccess, salt = encryptServiceAccessKey(password, accessPassword)
        cursor.execute("UPDATE users SET password = ?, access_key = ?, salt = ? WHERE user_id = ?",
                       (newHashedPassword, encryptedAccess, salt, user_id))
        connection.commit()
        connection.close()
        return True
    except:
        connection.close()
        return False

"""
Function used to retrieve a specific users user_id. User_id is assigned during registering.
"""
def retrieveUserId(username):
    connection, cursor = connectToDatabase()
    cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row != None:
        storedUserId = row[0]
        connection.close()
        return storedUserId
    else:
        #no users found
        connection.close()

"""
Function that retrieves an users password hash by id.
"""
def retrieveUserPassword(user_id):
    connection, cursor = connectToDatabase()
    cursor.execute("SELECT password FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row != None:
        storedHashedPassword = row[0]
        connection.close()
        return storedHashedPassword
    else:
        #no users found
        connection.close()

"""
Function that retrieves the users passwords table password and its salt by user_id.
The password is symmetrically encrypted using fernet. The fernet key used
 is generated using master password and the salt with PBKDF2. Used during login.
  OWASP password storage cheat sheet.
"""
def retrieveUserAccessKey(user_id):
    connection, cursor = connectToDatabase()
    cursor.execute("SELECT access_key, salt FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row != None:
        storedAccessKey = row[0]
        salt = row[1]
        connection.close()
        return storedAccessKey, salt
    else:
        #no users found
        connection.close()

"""
Rehashes and saves the hash of users master password in database every time they authenticate.
increases the work factor. OWASP password storage cheat sheet. 
"""
def rehashUserPassword(username, password):
    connection, cursor = connectToDatabase()
    try:
        rehashedPassword = hashUserPassword(password)
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (rehashedPassword, username))
        connection.commit()
        connection.close()
        #password rehashed
        return True
    except:
        #password rehashing failed
        connection.close()
        return False
    
"""
Adds credentials to new service to the database for an user specified by their id. Checks if service already
exist. Returns true if service was succesfully saved to the database. False if a service
exists already. Access password is used to symmetrically encrypt service name, service username
and service password with fernet. The fernet key is generated with PBKDF2 using access password
and random salt.  
"""      
def addService(user_id, accessPassword, serviceName, serviceUsername, servicePassword):
    connection, cursor = connectToDatabase()
    try:
        #check if user has already saved credentials for the service
        cursor.execute("SELECT service, salt FROM passwords WHERE user_id = ?", (user_id,))
        serviceExists = False
        userServices = cursor.fetchall()
        for service in userServices:
            serviceValue, saltValue = service
            storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
            storedServiceName = storedServiceName.decode()
            if storedServiceName == serviceName:
                serviceExists = True
                raise serviceExistsException
        #There were no previous credentials
        if serviceExists == False:
            #generate random salt
            salt = os.urandom(16)
            #use PBKDF2 to generate key using access password and salt
            key = makeKey(salt, accessPassword.encode())
            #encrypt service values with fernet using the key
            encryptedServiceName = encryptServiceWithKey(key, serviceName)
            encryptedServiceUsername = encryptServiceWithKey(key, serviceUsername)
            encryptedServicePassword = encryptServiceWithKey(key, servicePassword)
            #store service credentials into the database
            cursor.execute("INSERT INTO passwords (service, username, password, salt, user_id) VALUES (?, ?, ?, ?, ?)",
                      (encryptedServiceName, encryptedServiceUsername, encryptedServicePassword, salt, user_id))
            connection.commit()
            connection.close()
            return True
        #User has previous credentials
        else:
            connection.close()
            return False
    #error handling TODO: MAKE THIS MORE ROBUST
    except sqlite3.Error:
        #print("database error")
        connection.close()
        return False
    except serviceExistsException:
        #print("A password for this service already exists")
        connection.close()
        return False
    except:
        #print("An undefined error occured")
        connection.close()
        return False

"""
helper function that fethes all services of a user specified by id from the database. 
Services are still encrypted at this stage.
"""
def fetchServicesById(user_id):
    connection, cursor = connectToDatabase()
    
    cursor.execute("SELECT service, username, password, salt FROM passwords WHERE user_id = ?", (user_id,))
    userServices = cursor.fetchall()
    connection.close()
    return userServices

"""
Fetches all users service credentials from the database, decrypts them with the access password
and returs them as a list. Used when displaying saved service credentials.
"""
def fetchServiceData(user_id, accessPassword):
    userServices = fetchServicesById(user_id)
    serviceData = []
    for service in userServices:
        serviceValue, usernameValue, passwordValue, saltValue = service
        storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
        storedServiceName = storedServiceName.decode()
        row = [storedServiceName, usernameValue, passwordValue, saltValue]
        serviceData.append(row)
    return serviceData

"""
Function that checks if a service by a given name exists. returns a tuple specifying
if a server exists and its encrypted name. Use when updating. TODO: look into searchable 
encryption
"""       
def findServiceByName(user_id, accessPassword, serviceName):
    connection, cursor = connectToDatabase()
    
    #fetch all users services
    cursor.execute("SELECT service, salt FROM passwords WHERE user_id = ?", (user_id,))
    serviceExists = False
    encryptedName = ""
    userServices = cursor.fetchall()
    #loop through them all, decrypt each row and compare to the search string
    for service in userServices:
        serviceValue, saltValue = service
        storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
        storedServiceName = storedServiceName.decode()
        #there was a service by the given name
        if storedServiceName == serviceName:
            serviceExists = True
            encryptedName = serviceValue
    connection.close()
    return serviceExists, encryptedName

"""
Function used to update a specific services credentials. The new credentials are 
encrypted with the access password and new random salt. The new values are then 
updated in the database.
"""    
def updateServiceData(user_id, accessPassword, serviceName, newUsername, newPassword):
    #check if service exists. Should newer return false. False means database has been 
    #tampered with
    exists, encryptedName = findServiceByName(user_id, accessPassword, serviceName)
    if exists:
        #generate new salt and encrypt new credentials
        salt = os.urandom(16)
        key = makeKey(salt, accessPassword.encode())
        encryptedServiceName = encryptServiceWithKey(key, serviceName)
        encryptedServiceUsername = encryptServiceWithKey(key, newUsername)
        encryptedServicePassword = encryptServiceWithKey(key, newPassword)
        connection, cursor = connectToDatabase()
        #update the row in the database
        cursor.execute('UPDATE passwords SET service = ?, username = ?, password = ?, salt = ? WHERE user_id = ? AND service = ?',
                           (encryptedServiceName, encryptedServiceUsername, encryptedServicePassword, salt, user_id, encryptedName))
        #commit changes and close connection
        connection.commit()
        connection.close()
        return True
    else:
        #print("service was not found")
        return False

"""
Deletes a specific service credentials from the database
"""
def deleteServiceData(user_id, accessPassword, serviceName):
    exists, encryptedName = findServiceByName(user_id, accessPassword, serviceName) 
    if exists:
        connection, cursor = connectToDatabase()
        cursor.execute("DELETE FROM passwords WHERE user_id = ? AND service = ?",
                      (user_id, encryptedName))
        connection.commit()
        connection.close()
        return True
    else:
        #print("cant delete what does not exist")
        return False

"""
Deletes all passwords from the passwords table belonging to a specific user.
"""
def deleteAllServiceDataById(user_id):
    connection, cursor = connectToDatabase()
    try:
        cursor.execute("DELETE FROM passwords WHERE user_id = ?",
                          (user_id,))
        connection.commit()
        connection.close()
        return True
    except:
        connection.close()
        return False

"""
Deletes the users entry from users table by provided id
"""
def deleteUserById(user_id):
    connection, cursor = connectToDatabase()
    try:
        cursor.execute("DELETE FROM users WHERE user_id = ?",
                          (user_id,))
        connection.commit()
        connection.close()
        return True
    except:
        connection.close()
        return False
    