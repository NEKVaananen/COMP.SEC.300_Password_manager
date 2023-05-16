"""
Graphical user interface of the password manager
"""
import tkinter as tk
from UILogic import logicHandler
import pyperclip as pc


#initialize application GUI
mainWindow = tk.Tk()
mainWindow.geometry("500x600")
mainWindow.title("Amazing Password Manager")

frame = tk.Frame(mainWindow)
frame.place(relx = 0, rely = 0)
logic = logicHandler()
totalLoginTries = 0

"""
Helper function that calls functions from UILogic class to check credentils when
registering a new user. 
"""
def registerUser(username, password):
    #check password strength
    isStrong = logic.checkPasswordStrength(password)
    if(len(username) > 0):
        if(isStrong):
            success = logic.registerNewUser(username, password)
            if(success):
                startPage()
            else:
                tk.messagebox.showwarning("Warning", "Username is already taken!")
        else:
            tk.messagebox.showwarning("Warning", "Password is too weak!")
    else:
        tk.messagebox.showwarning("Warning", "Please provide a username!")

"""
Helper function that logs the user in and displays the mainpage if login is succesful.
An error message is displayed if credentials do not match.
see OWASP Authentication and Error Messages
"""
def loginUser(username, password):
    global totalLoginTries
    loginSuccess = logic.logUserIn(username, password)
    #login was succesful reset login tries and move to main page
    if loginSuccess:
        totalLoginTries = 0
        mainPage()
    #credentials were incorrect. increase try counter and disable login until we have waited
    #as many seconds as there were tries.
    #Offer Brute force attack prevention
    else:
        totalLoginTries += 1
        errorMessage = "Incorrect username or password. Try again after {} seconds.".format(totalLoginTries)
        tk.messagebox.showwarning("Warning", errorMessage)
        loginButton.config(state="disabled")
        mainWindow.after(totalLoginTries*1000, loginButton.config(state="normal"))

"""
Helper function for adding a new password to a service.
Confirms if credentials were added correctly
"""
def addPassword(service, username, password):
    #check that all fields are filled. We do not check strength here to not break
    #compatibility with other password guidelines
    if(len(service) > 0 and len(username) > 0 and len(password) > 0):
        if(logic.insertServiceToDatabase(service, username, password)):
            clearFrame()
            label=tk.Label(frame,text = 'Credentials added succesfully!')
            label.grid(row = 0, column = 0)
            backButton = tk.Button(frame, text="Main page", command=mainPage)
            backButton.grid(column = 0, row = 1)
        else:
            clearFrame()
            label=tk.Label(frame,text = 'An error occured while storing credentials!')
            label.grid(row = 0, column = 0)
            backButton = tk.Button(frame, text="Main page", command=mainPage)
            backButton.grid(column = 0, row = 1)
    else:
        tk.messagebox.showwarning("Warning", "Please fill all fields!")

"""
Helper function responsible for clearing the page of widgets before we render new view
"""
def clearFrame():
    for children in frame.winfo_children():
       children.destroy()
    frame.pack_forget()
    
"""
The first page rendered. User can either register or log in.
"""
def startPage():
    clearFrame()
    #Create database if one does not exist
    logic.initializeApplicationDatabase()
    
    label=tk.Label(frame,text = 'Welcome to APM!')
    label.grid(row = 0, column = 0)
    loginButton = tk.Button(frame, text="Login", command=loginPage)
    loginButton.grid(column = 0, row = 1)
    registerButton = tk.Button(frame, text="Register", command=registerPage)
    registerButton.grid(column = 0, row = 2)

"""
A view for logging in a registered user
"""
def loginPage():
    clearFrame()
    label=tk.Label(frame,text = 'Login page')
    label.grid(row = 0, column = 0)
    
    usernameText = tk.Label(frame, text = "User Name:")
    usernameText.grid(row = 1, column = 0)
    username = tk.StringVar()
    usernameEntry = tk.Entry(frame, textvariable = username)
    usernameEntry.grid(row = 1, column = 1)
    
    passwordText = tk.Label(frame, text = "Password:")
    passwordText.grid(row = 2, column = 0)
    password = tk.StringVar()
    passwordEntry = tk.Entry(frame, textvariable = password, show='*')
    passwordEntry.grid(row = 2, column = 1)
    
    global loginButton
    loginButton = tk.Button(
        frame, text='login', command = lambda: loginUser(username.get(), password.get()))
    loginButton.grid(row = 3, column = 0)
    backButton=tk.Button(frame, text='Back', command=startPage)
    backButton.grid(row = 4, column = 0)

"""
A view for registering a new user to the system
"""
def registerPage():
    clearFrame()
    label=tk.Label(frame,text = 'Register page')
    label.grid(row = 0, column = 0)
    
    usernameText = tk.Label(frame, text = "User Name:")
    usernameText.grid(row = 1, column = 0)
    username = tk.StringVar()
    usernameEntry = tk.Entry(frame, textvariable = username)
    usernameEntry.grid(row = 1, column = 1)
    
    passwordText = tk.Label(frame, text = "Password:")
    passwordText.grid(row = 2, column = 0)
    password = tk.StringVar()
    passwordEntry = tk.Entry(frame, textvariable = password, show='*')
    passwordEntry.grid(row = 2, column = 1)
    
    registerButton = tk.Button(
        frame, text='Register', command = lambda: registerUser(username.get(), password.get()))
    registerButton.grid(row = 3, column = 0)
    
    backButton=tk.Button(frame, text='Back', command=startPage)
    backButton.grid(row = 4, column = 0)
    
    textBlock = tk.Text(frame, height=6, width=30)
    textBlock.insert(tk.END, "The master password must have:\n-At least 12 characters\n-uppercase letter\n-lowercase letter\n-number\n-symbol")
    textBlock.config(state=tk.DISABLED)
    textBlock.grid(row = 5, column = 1)

"""
Helper function for clearing UILogic class instance of logged in users credentials and 
to return them to the startPage
"""
def logOut():
    logic.clearCredentials()
    startPage()

"""
Helper function for account deletion. Prompts user to confirm and commands UILogic instance
to handle the deletion. Upon succesful deletion the logOut function is called.
"""
def accountDeleteHelper():
    userResponse = tk.messagebox.askquestion("Question",
                 "Are you sure you want to delete your account and all \nassociated services?\nData cannot be recovered afterwards.",icon="question")
    if userResponse == "yes":
        serviceSuccess, userSuccess = logic.deleteAccount()
        #Deletion was succesful. Log out.
        if(serviceSuccess and userSuccess):
            logOut()
        #Something went wrong. Construct error message and warn user.
        else:
            errorMessage = "Account deletion failed!\nPlease contact software provider."
            if(serviceSuccess == False):
                errorMessage += "\nThere was an error deleting service data"
            if(userSuccess == False):
                errorMessage += "\nThere was an error deleting user data"
            tk.messagebox.showwarning("Warning", errorMessage)
    
"""
Helper function for changing users master password
"""
def userUpdateHelper(oldPassword, newPassword, repeatNewPassword):
    if(newPassword == repeatNewPassword):
        isStrong = logic.checkPasswordStrength(newPassword)
        if(isStrong):
            oldPasswordCheck = logic.passwordUpdateCheck(oldPassword)
            if(oldPasswordCheck):
                updateSuccess = logic.updateMasterPassword(newPassword)
                if(updateSuccess):
                    tk.messagebox.showwarning("Warning", "Password succesfully changed!")
                else:
                    tk.messagebox.showwarning("Warning", "A database error occured")
            else:
                tk.messagebox.showwarning("Warning", "Old password was not accepted")
        else:
            tk.messagebox.showwarning("Warning", "Please provide a strong password!")
            
    else:
        tk.messagebox.showwarning("Warning", "Make sure new password fields match!")

"""
View for changing the master password
"""
def userUpdateView():
    clearFrame()
    label=tk.Label(frame,text='Change your master password')
    label.grid(row = 0, column = 0)
    
    oldPasswordText = tk.Label(frame, text = "Old password:")
    oldPasswordText.grid(row = 1, column = 0)
    oldPassword = tk.StringVar()
    oldPasswordEntry = tk.Entry(frame, textvariable = oldPassword, show='*')
    oldPasswordEntry.grid(row = 1, column = 1)
    
    newPasswordText = tk.Label(frame, text = "New password:")
    newPasswordText.grid(row = 2, column = 0)
    newPassword = tk.StringVar()
    newPasswordEntry = tk.Entry(frame, textvariable = newPassword, show='*')
    newPasswordEntry.grid(row = 2, column = 1)
    
    repeatPasswordText = tk.Label(frame, text = "repeat new password:")
    repeatPasswordText.grid(row = 3, column = 0)
    repeatPassword = tk.StringVar()
    repeatPasswordEntry = tk.Entry(frame, textvariable = repeatPassword, show='*')
    repeatPasswordEntry.grid(row = 3, column = 1)
    
    saveButton =  tk.Button(frame, text='Save', command = lambda: userUpdateHelper(
        oldPassword.get(), newPassword.get(), repeatPassword.get()))
    saveButton.grid(row = 4, column = 0)
    
    backButton = tk.Button(frame, text='Back', command=mainPage)
    backButton.grid(row = 5, column = 0)
    
    textBlock = tk.Text(frame, height=6, width=30)
    textBlock.insert(tk.END, "The master password must have:\n-At least 12 characters\n-uppercase letter\n-lowercase letter\n-number\n-symbol")
    textBlock.config(state=tk.DISABLED)
    textBlock.grid(row = 6, column = 1)

"""
Generates a cryptographically safe 12 character password and pastes it to the clipboard
"""    
def randomHelper():
    copyToClipboard(logic.generateRandomPassword())
    tk.messagebox.showwarning("Warning", "Random password was generated to your clipboard!")

"""
Displays the main page after a succesful login.
User can add new password to a service or View all saved services.
"""
def mainPage():
    clearFrame()
    label=tk.Label(frame,text='main page')
    label.grid(row = 0, column = 0)
    bt1=tk.Button(frame, text='Add new password',command=addPasswordPage)
    bt1.grid(column=0,row=1)
    bt2=tk.Button(frame, text='stored passwords', command=viewServicesPage)
    bt2.grid(column=0,row=2)
    bt3 = tk.Button(frame, text = "Change master password", command = userUpdateView)
    bt3.grid(column = 0, row = 3)
    bt4 = tk.Button(frame, text = "delete account", command = accountDeleteHelper)
    bt4.grid(column = 0, row = 4)
    bt5=tk.Button(frame, text='log out', command=logOut)
    bt5.grid(column=0,row=5)
    
    random = tk.Button(frame, text = "generate secure random password", command = randomHelper)
    random.grid(column = 4, row = 1)
    
"""
A view where new service credentials can be added to the database
"""
def addPasswordPage():
    clearFrame()
    label=tk.Label(frame,text='Add new password')
    label.grid(row = 0, column = 0)
    
    serviceNameText = tk.Label(frame, text = "Service Name:")
    serviceNameText.grid(row = 1, column = 0)
    serviceName = tk.StringVar()
    serviceNameEntry = tk.Entry(frame, textvariable = serviceName)
    serviceNameEntry.grid(row = 1, column = 1)
    
    serviceUsernameText = tk.Label(frame, text = "Service  Username:")
    serviceUsernameText.grid(row = 2, column = 0)
    serviceUsername = tk.StringVar()
    serviceUsernameEntry = tk.Entry(frame, textvariable = serviceUsername)
    serviceUsernameEntry.grid(row = 2, column = 1)
    
    passwordText = tk.Label(frame, text = "Password:")
    passwordText.grid(row = 3, column = 0)
    password = tk.StringVar()
    passwordEntry = tk.Entry(frame, textvariable = password, show='*')
    passwordEntry.grid(row = 3, column = 1)
    
    bt1=tk.Button(frame, text='Save', command = lambda: addPassword(
        serviceName.get(), serviceUsername.get(), password.get()))
    bt1.grid(row = 4, column = 0)
    
    bt2=tk.Button(frame, text='Back', command=mainPage)
    bt2.grid(row = 5, column = 0)

"""
Helper function that is used to copy a credential to the clipboard.
Uses pythons pyperclip library
"""
def copyToClipboard(text):
    pc.copy(text)

"""
A view where user can copy a services username or password to clipboard by clicking
the associated button.
"""
def servicePage(username, password, salt):
    clearFrame()
    credentials = logic.decryptCredentials(username, password, salt)
    label=tk.Label(frame,text='Click to copy:')
    label.grid(row = 0, column = 0)
    usernameButton = tk.Button(frame, text="username", command=lambda u=credentials[0]:copyToClipboard(u))
    usernameButton.grid(row = 1, column = 0)
    passwordButton = tk.Button(frame, text="password", command=lambda p=credentials[1]:copyToClipboard(p))
    passwordButton.grid(row = 2, column = 0)
    bt2=tk.Button(frame, text='Back', command=viewServicesPage)
    bt2.grid(row = 0, column = 2)

"""
Helper for service deletion. Confirms the deletion with user before proceeding.
"""    
def serviceDeleteHelper(service):
    userResponse = tk.messagebox.askquestion("Question",
                 "Do you really want to delete?",icon="question")
    if userResponse == "yes":
        logic.deleteService(service)
        viewServicesPage()

"""
Helper for service credential update. Confirms the field with user before proceeding.
""" 
def serviceUpdateHelper(service, username, password):
    if(len(service) > 0 and len(username) > 0 and len(password) > 0):
        if (logic.updateService(service, username, password)):
            #update success
            viewServicesPage()
            tk.messagebox.showwarning("Warning", "Update was succesful!")
        else:
            #update failure
            viewServicesPage()
            tk.messagebox.showwarning("Warning", "Update failed!")
    else:
        tk.messagebox.showwarning("Warning", "Please fill all fields!")
    
"""
A view for updating the credentials to a service
"""      
def serviceUpdateView(service):
    clearFrame()
    label=tk.Label(frame,text='Update service credentials')
    label.grid(row = 0, column = 0)
    labelText = "Service Name: {}".format(service)
    
    serviceNameText = tk.Label(frame, text = labelText)
    serviceNameText.grid(row = 1, column = 0)
    
    serviceUsernameText = tk.Label(frame, text = "New  Username:")
    serviceUsernameText.grid(row = 2, column = 0)
    serviceUsername = tk.StringVar()
    serviceUsernameEntry = tk.Entry(frame, textvariable = serviceUsername)
    serviceUsernameEntry.grid(row = 2, column = 1)
    
    passwordText = tk.Label(frame, text = "New Password:")
    passwordText.grid(row = 3, column = 0)
    password = tk.StringVar()
    passwordEntry = tk.Entry(frame, textvariable = password, show='*')
    passwordEntry.grid(row = 3, column = 1)
    
    saveButton=tk.Button(frame, text='Save', command = lambda: serviceUpdateHelper(
        service, serviceUsername.get(), password.get()))
    saveButton.grid(row = 4, column = 0)
    
    backButton=tk.Button(frame, text='Back', command=viewServicesPage)
    backButton.grid(row = 5, column = 0)
    
"""
A view where user can view all credentials they have saved to the database. 
Clicking a credential renders the associated servicePage.
""" 
def viewServicesPage():
    clearFrame()
    serviceData = logic.getServices()
    label=tk.Label(frame,text='Saved services:')
    label.grid(row = 0, column = 0)
    i = 1
    if serviceData != None:
        for item in serviceData:
            label = tk.Label(frame, text=item[0])
            label.grid(row = i, column = 0)
            viewButton = tk.Button(frame, text = "view credentials", command=lambda u=item[1], p=item[2], s=item[3]:servicePage(u, p, s))
            viewButton.grid(row = i, column = 1)
            updateButton = tk.Button(frame, text = "update credentials", command=lambda n=item[0]:serviceUpdateView(n))
            updateButton.grid(row = i, column = 3)
            deleteButton = tk.Button(frame, text = "delete credentials", command=lambda n=item[0]:serviceDeleteHelper(n))
            deleteButton.grid(row = i, column = 4)
            i = i + 1
    
    bt2=tk.Button(frame, text='Back', command=mainPage)
    bt2.grid(row = 0, column = 2)

command = startPage()

mainWindow.mainloop()