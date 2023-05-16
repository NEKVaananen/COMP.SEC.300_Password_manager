# -*- coding: utf-8 -*-
"""
Handles the internal logic of the password manager and keeps user state
"""
import os
from databaseHandler import createDatabase, storeNewUser, retrieveUserId, retrieveUserPassword, verifyUserPassword, addService, retrieveUserAccessKey, decryptServiceAccessKey, fetchServiceData, rehashUserPassword, deleteServiceData, updateServiceData

class logicHandler:

    loggedInUserId = None
    loggedInAccessPassword = None
    
    """
    creates the database if it does not exist in filepath
    """
    def initializeApplicationDatabase(self):
        if not os.path.exists('passwords.db'):
            createDatabase()
            print("database created")
        else:
            print("database exists")
            
    """
    Checks the strength of a password.
    returns true if password is strong, false if is not.
    """
    def checkPasswordStrength(self, password):
        length = 12
        hasUppercase = False
        hasLowercase = False
        hasNumber = False
        hasSymbol = False

        #Check the password length against the guidelines
        if len(password) < length:
            return False
        
        #loop and check all characters against the guidelines
        for char in password:
            if char.isupper():
                hasUppercase = True
            elif char.islower():
                hasLowercase = True
            elif char.isdigit():
                hasNumber = True
            elif char in "!@#$%^&*()_-+={}[]|\:;\"'<>,.?/":
                hasSymbol = True
        #if password fulfills guidelines return true
        if(hasUppercase and hasLowercase and hasNumber and hasSymbol):
            return True
        #return false if password is deemed too weak
        else:
            return False
    
    """
    register new user to database
    """
    def registerNewUser(self, username, password):
        storeNewUser(username, password)
    
    """
    Login user if they have registered
    returns false if user does not exist or credentials do not match
    """
    def logUserIn(self, username, password):
        storedId = retrieveUserId(username)
        #if there is no stored id user does not exist
        if(storedId == None):
            return False
        storedUserPassword = retrieveUserPassword(storedId)
        loginSuccess = verifyUserPassword(storedUserPassword, password)
        if(loginSuccess):
            print("login success")
            #retrieve users service database access password
            storedAccessKey, salt = retrieveUserAccessKey(storedId)
            #decrypt it using master password and stored salt
            decryptedAccess = decryptServiceAccessKey(password, storedAccessKey, salt)
            decryptedAccess = decryptedAccess.decode()
            #store user_id to the class 
            logicHandler.loggedInUserId = storedId
            #store database access to the class
            logicHandler.loggedInAccessPassword = decryptedAccess
            #increase work factor and rehash master password
            rehashUserPassword(username, password)
            return True
        else:
            print("login unsuccesful")
            return False
    
    """
    Insert new service to database
    """
    def insertServiceToDatabase(self, serviceName, serviceUsername, servicePassword):
        success = addService(self.loggedInUserId, self.loggedInAccessPassword, serviceName, serviceUsername, servicePassword)
        if(success):
            return True
        else:
            return False
        
    def getServices(self):
        serviceData = fetchServiceData(self.loggedInUserId, self.loggedInAccessPassword)
        #print(serviceData)
        return serviceData
    
    def decryptCredentials(self, username, password, salt):
        username = decryptServiceAccessKey(self.loggedInAccessPassword, username, salt)
        username = username.decode()
        password = decryptServiceAccessKey(self.loggedInAccessPassword, password, salt)
        password = password.decode()
        decryptedCredentials = [username, password]
        return decryptedCredentials
        
    
    def clearCredentials(self):
        logicHandler.loggedInUserId = None
        logicHandler.loggedInAccessPassword = None
        
    def deleteService(self, serviceName):
        return deleteServiceData(self.loggedInUserId, self.loggedInAccessPassword, serviceName)
    
    def updateService(self, serviceName, newUsername, newPassword):
        return updateServiceData(self.loggedInUserId, self.loggedInAccessPassword, serviceName, newUsername, newPassword)
            