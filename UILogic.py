# -*- coding: utf-8 -*-
"""
Class that routes the internal logic of the password manager and keeps user state
"""
import string
import secrets
import os
from databaseHandler import createDatabase, storeNewUser, retrieveUserId, retrieveUserPassword, verifyUserPassword, addService, retrieveUserAccessKey, decryptServiceAccessKey, fetchServiceData, rehashUserPassword, deleteServiceData, updateServiceData, deleteAllServiceDataById, deleteUserById, updateUserPassword

class logicHandler:
    
    #class variables that track the currently logged in users id and service database password
    #they receive an actual value upon succesful authenti
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
        registerSuccess = storeNewUser(username, password)
        return registerSuccess
    
    """
    Login user if they have registered
    returns false if user does not exist or credentials do not match
    Password is rehashed after a succesful authentication (OWASP work factor upgrade)
    """
    def logUserIn(self, username, password):
        storedId = retrieveUserId(username)
        #if there is no stored id the user does not exist
        if(storedId == None):
            return False
        storedUserPassword = retrieveUserPassword(storedId)
        loginSuccess = verifyUserPassword(storedUserPassword, password)
        if(loginSuccess):
            #login success
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
            #login unsuccesful
            return False
    """
    Used when updating master password. checks that the user provided old password 
    matches with the stored one.
    Returns boolean value true if passwords match, false if they do not.
    """
    def passwordUpdateCheck(self, userPassword):
        storedUserPassword = retrieveUserPassword(self.loggedInUserId)
        checkSuccess = verifyUserPassword(storedUserPassword, userPassword)
        return checkSuccess
        
    """
    Insert new service credentials to the database
    """
    def insertServiceToDatabase(self, serviceName, serviceUsername, servicePassword):
        success = addService(self.loggedInUserId, self.loggedInAccessPassword, serviceName, serviceUsername, servicePassword)
        if(success):
            return True
        else:
            return False
    """
    Retrieves a list of users stored service credentials from database
    """
    def getServices(self):
        serviceData = fetchServiceData(self.loggedInUserId, self.loggedInAccessPassword)
        #print(serviceData)
        return serviceData
    
    """
    Used to decrypt a row of credentials retrieved from the database
    """
    def decryptCredentials(self, username, password, salt):
        username = decryptServiceAccessKey(self.loggedInAccessPassword, username, salt)
        username = username.decode()
        password = decryptServiceAccessKey(self.loggedInAccessPassword, password, salt)
        password = password.decode()
        decryptedCredentials = [username, password]
        return decryptedCredentials
        
    """
    Used when user logs out to clear the id and password
    """
    def clearCredentials(self):
        logicHandler.loggedInUserId = None
        logicHandler.loggedInAccessPassword = None
        
    """
    GUI calls this function when deleting a specific services credentials. 
    Returns the boolean value received from databaseHandler
    """    
    def deleteService(self, serviceName):
        return deleteServiceData(self.loggedInUserId, self.loggedInAccessPassword, serviceName)
    
    """
    GUI calls this function when updating service credentials. 
    Returns the boolean value received from databaseHandler
    """
    def updateService(self, serviceName, newUsername, newPassword):
        return updateServiceData(self.loggedInUserId, self.loggedInAccessPassword, serviceName, newUsername, newPassword)
    
    """
    GUI calls this function when deleting an account. 
    Returns the boolean values received from databaseHandler
    """
    def deleteAccount(self):
        serviceDelete = deleteAllServiceDataById(self.loggedInUserId)
        userDelete = deleteUserById(self.loggedInUserId)
        return serviceDelete, userDelete
    """
    GUI calls this function when updating master password. 
    Returns the boolean value received from databaseHandler
    """
    def updateMasterPassword(self, newPassword):
        return updateUserPassword(self.loggedInUserId, newPassword, self.loggedInAccessPassword)
    """
    Generates a cryptographically safe random password that abides by the rules set
    in checkPasswordStrength function.
    returns the generated password.
    """
    def generateRandomPassword(self):
        #define characters that are accepted
        characters = string.ascii_letters + string.digits + string.punctuation
    
        #ensure at least one uppercase, one lowercase, one number, and one symbol
        password = secrets.choice(string.ascii_uppercase)
        password += secrets.choice(string.ascii_lowercase)
        password += secrets.choice(string.digits)
        password += secrets.choice(string.punctuation)
        
        #generate the rest
        for x in range(8):
            password += secrets.choice(characters)
    
        #make the password into a list
        passwordList = list(password)
        #shuffle the list
        secrets.SystemRandom().shuffle(passwordList)
        #back to string
        password = ''.join(passwordList)
    
        return password
   