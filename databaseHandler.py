# -*- coding: utf-8 -*-
"""
Handles database interaction
"""

import secrets
import sqlite3
import os
from encryptionHandler import hashUserPassword, verifyUserPassword, encryptServiceAccessKey, decryptServiceAccessKey, makeKey, encryptServiceWithKey

class serviceExistsException(Exception):
    "user has already saved credentials for this service"
    pass

def connectToDatabase():
    connection = sqlite3.connect('passwords.db')
    cursor = connection.cursor()
    return connection, cursor

def generateRandomPassword():
    password_length = 32
    randomPassword = secrets.token_urlsafe(password_length)
    return randomPassword

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

def storeNewUser(username, password):
    connection, cursor = connectToDatabase()
    # Check if an user already exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    #if user does not exist
    if result is None:
        #Hash users master password and generate password to service table
        hashedPassword = hashUserPassword(password)
        accessPassword = generateRandomPassword()
        #encrypt service table password with users password
        encryptedAccess, salt = encryptServiceAccessKey(password, accessPassword)
        
        #store new user and close connection
        cursor.execute("INSERT INTO users (username, password, access_key, salt) VALUES (?, ?, ?, ?)",
                       (username, hashedPassword, encryptedAccess, salt))
        connection.commit()
        connection.close()
    #user exists
    else:
        print("username is already taken!")
        connection.close()
    
def updateUserPassword(username, password):
    newHashedPassword = hashUserPassword(password)
    conn, cursor = connectToDatabase()
    conn.execute('UPDATE users SET password = ? WHERE username = ?', (newHashedPassword, username))
    conn.commit()
    conn.close()
        
def retrieveUserId(username):
    conn, cursor = connectToDatabase()
    cursor.execute("SELECT user_id FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    if row != None:
        storedUserId = row[0]
        conn.close()
        return storedUserId
    else:
        print("no users found")
        conn.close()
        
def retrieveUserPassword(user_id):
    conn, cursor = connectToDatabase()
    cursor.execute("SELECT password FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row != None:
        storedHashedPassword = row[0]
        conn.close()
        return storedHashedPassword
    else:
        print("no users found")
        conn.close()
        
def retrieveUserAccessKey(user_id):
    conn, cursor = connectToDatabase()
    cursor.execute("SELECT access_key, salt FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row != None:
        storedAccessKey = row[0]
        salt = row[1]
        conn.close()
        return storedAccessKey, salt
    else:
        print("no users found")
        conn.close()

"""
Rehashes and saves the hash of users master password in database every time they authenticate.
increases the work factor.
"""
def rehashUserPassword(username, password):
    connection, cursor = connectToDatabase()
    try:
        rehashedPassword = hashUserPassword(password)
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (rehashedPassword, username))
        connection.commit()
        connection.close()
        print("password rehashed")
        return True
    except:
        print("password rehashing failed")
        connection.close()
        return False
    
"""
Adds a new service to the database for an user specified by their id.
"""      
def addService(user_id, accessPassword, serviceName, serviceUsername, servicePassword):
    connection, cursor = connectToDatabase()
    try:
        cursor.execute("SELECT service, salt FROM passwords WHERE user_id = ?", (user_id,))
        serviceExists = False
        userServices = cursor.fetchall()
        for service in userServices:
            serviceValue, saltValue = service
            storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
            storedServiceName = storedServiceName.decode()
            print(storedServiceName)
            if storedServiceName == serviceName:
                serviceExists = True
                raise serviceExistsException
    
        if serviceExists == False:
            salt = os.urandom(16)
            key = makeKey(salt, accessPassword.encode())
            encryptedServiceName = encryptServiceWithKey(key, serviceName)
            encryptedServiceUsername = encryptServiceWithKey(key, serviceUsername)
            encryptedServicePassword = encryptServiceWithKey(key, servicePassword)
            #test = "{}, {}, {}".format(encryptedServiceName, encryptedServiceUsername, encryptedServicePassword)
            #print(test)
            cursor.execute("INSERT INTO passwords (service, username, password, salt, user_id) VALUES (?, ?, ?, ?, ?)",
                      (encryptedServiceName, encryptedServiceUsername, encryptedServicePassword, salt, user_id))
            connection.commit()
            connection.close()
            return True
        else:
            connection.close()
            return False
    except sqlite3.Error:
        print("database error")
        return False
    except serviceExistsException:
        print("A password for this service already exists")
        connection.close()
        return False
    except:
        print("An undefined error occured")
        connection.close()
        return False
        
def fetchServicesById(user_id):
    connection, cursor = connectToDatabase()
    
    cursor.execute("SELECT service, username, password, salt FROM passwords WHERE user_id = ?", (user_id,))
    userServices = cursor.fetchall()
    connection.close()
    return userServices

def fetchServiceData(user_id, accessPassword):
    userServices = fetchServicesById(user_id)
    serviceData = []
    for service in userServices:
        serviceValue, usernameValue, passwordValue, saltValue = service
        storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
        storedServiceName = storedServiceName.decode()
        row = [storedServiceName, usernameValue, passwordValue, saltValue]
        serviceData.append(row)
        
        #test = "{}, {}, {}".format(storedServiceName, storedServiceUsername, storedServicePassword)
        #print(test)
    return serviceData
        
def findServiceByName(user_id, accessPassword, serviceName):
    connection, cursor = connectToDatabase()
    
    cursor.execute("SELECT service, salt FROM passwords WHERE user_id = ?", (user_id,))
    serviceExists = False
    encryptedName = ""
    userServices = cursor.fetchall()
    for service in userServices:
        serviceValue, saltValue = service
        storedServiceName = decryptServiceAccessKey(accessPassword, serviceValue, saltValue)
        storedServiceName = storedServiceName.decode()
        if storedServiceName == serviceName:
            serviceExists = True
            encryptedName = serviceValue
    connection.close()
    return serviceExists, encryptedName
    
def updateServiceData(user_id, accessPassword, serviceName, newUsername, newPassword):
    exists, encryptedName = findServiceByName(user_id, accessPassword, serviceName)
    if exists:
        salt = os.urandom(16)
        key = makeKey(salt, accessPassword.encode())
        encryptedServiceName = encryptServiceWithKey(key, serviceName)
        encryptedServiceUsername = encryptServiceWithKey(key, newUsername)
        encryptedServicePassword = encryptServiceWithKey(key, newPassword)
        connection, cursor = connectToDatabase()
        cursor.execute('UPDATE passwords SET service = ?, username = ?, password = ?, salt = ? WHERE user_id = ? AND service = ?',
                           (encryptedServiceName, encryptedServiceUsername, encryptedServicePassword, salt, user_id, encryptedName))
        connection.commit()
        connection.close()
        return True
    else:
        print("service was not found")
        return False

def deleteServiceData(user_id, accessPassword, serviceName):
    exists, encryptedName = findServiceByName(user_id, accessPassword, serviceName) 
    if exists:
        connection, cursor = connectToDatabase()
        cursor.execute('DELETE FROM passwords WHERE user_id = ? AND service = ?',
                      (user_id, encryptedName))
        connection.commit()
        connection.close()
        return True
    else:
        print("cant delete what does not exist")
        return False
    
def testServiceAccess(storedId, userPassword):
    serviceName = "google"
    serviceUsername = "testi"
    servicePassword = "example_password"
    service2 = "greatservice"
    service2Username = "testi2"
    service2Password = "example_password2"
    newUsername = "better username"
    newPassword = "better password"
    
    storedAccessKey, salt = retrieveUserAccessKey(storedId)
    decryptedAccess = decryptServiceAccessKey(userPassword, storedAccessKey, salt)
    decryptedAccess = decryptedAccess.decode()
    addService(storedId, decryptedAccess, serviceName, serviceUsername, servicePassword)
    addService(storedId, decryptedAccess, service2, service2Username, service2Password)
    fetchServiceData(storedId, decryptedAccess)
    print("now we test updating")
    updateServiceData(storedId, decryptedAccess, serviceName, newUsername, newPassword)
    fetchServiceData(storedId, decryptedAccess)
    print("testing delete")
    deleteServiceData(storedId, decryptedAccess, serviceName)
    fetchServiceData(storedId, decryptedAccess)

def testUsers(username, userPassword):
    createDatabase()
    
    storeNewUser(username, userPassword)
    
    storedId = retrieveUserId(username)
    storedUserPassword = retrieveUserPassword(storedId)
    verifyUserPassword(storedUserPassword, userPassword)
    
    
    storedAccessKey, salt = retrieveUserAccessKey(storedId)
    decryptedAccess = decryptServiceAccessKey(userPassword, storedAccessKey, salt)
    decryptedAccess = decryptedAccess.decode()
    
    
def testAll():
    username = "username"
    userPassword = "my_password"
    testUsers(username, userPassword)
    storedId = retrieveUserId(username)
    testServiceAccess(storedId, userPassword)
    
    
#testAll()




