import bcrypt
import pickle

def create_user(username, password, users, user_salts):
    if not username in users:
        user_salts[username] = bcrypt.gensalt()
        users[username] = bcrypt.hashpw(str.encode(password), user_salts[username])
        return users, user_salts
    else:
        return False

def update_user(username, password, newpassword, users, user_salts):
    if username in users and bcrypyt.hashpw(password, user_salts[username]) == users[username]:
        user_salts[username] = bcrypt.gensalt()
        users[username] = bcrypt.hashpw(newpassword, user_salts[username])
        return users, user_salts
    else:
        return False

def change_pass(users, user_salts):
        uname = input("Username: ")
        pword = input("Old password: ")
        newp = input("New password: ")
        newp2 = input("Confirm new password: ")
        
        if newp == newp2:
            b = update_user(uname, pword, newpassord, users, user_salts)
            if b:
                users, user_salts = b
                save_users(users)
                save_salts(user_salts)
                print("Success!")
            else:
                print("Incorrect username or password")
        else:
            print("Passwords do not match")
            change_pass(users, user_salts)
    

def check_pass(username, password, users, user_salts):
    password = str.encode(password)
    try:
        return users[username] == bcrypt.hashpw(password, user_salts[username])
    except: return False
   
def save_users(users):
    with open("userdb.pickle", "wb") as userdb:
        pickle.dump(users, userdb)

def save_salts(user_salts):
    with open("user_salts_db.pickle", "wb") as user_salts_db:
        pickle.dump(user_salts, user_salts_db)

def load_dic(db):
    return pickle.load(db)

def login(users, user_salts):
    uname = input("Enter your username: ")
    pword = input("Enter your password: ")
    if check_pass(uname, pword, users, user_salts):
        print("Success!")
    else:
        print("Failure.")
        main()

def newuser(users, user_salts):
    uname = input("Enter your desired username: ")
    pword = input("Enter your password: ")
    pword2 = input("Confirm password: ")
    if not pword == pword2:
        print("Try again.")
        newuser(users, user_salts)
    else:
        b = create_user(uname, pword, users, user_salts)
        if not b:
            print("Username already exists.")
        else:
            print("Success")
            users, user_salts = b
    
    save_users(users)
    save_salts(user_salts)

def main():
    #see if user dictionary already exists; if so, load it using pickle - if not, it's an empty dictionary.
    try:
        with open("userdb.pickle", "rb") as userdb:
            users = load_dic(userdb)
    except: users = {}

    #see if salt dictionary already exists; if so, load it using pickle - if not, it's an empty dictionary.
    try:
        with open("user_salts_db.pickle", "rb") as user_salts_db:
            user_salts = load_dic(user_salts_db)
    except: user_salts = {}
    
    #see if user wants to log in, register, or change their password.    
    purpose = input("Log in, register, or change password?")
    
    if purpose.lower() == "log in":
        login(users, user_salts)
    elif purpose.lower() == "register":
        newuser(users, user_salts)
    else:
        change_pass(users, user_salts)

if __name__ == "__main__":
    main()
