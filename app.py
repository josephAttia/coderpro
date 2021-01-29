from flask import Flask, session, redirect, url_for, request, render_template, make_response
from markupsafe import escape
import pyrebase

app = Flask(__name__)   
app.secret_key = "Joseph@2005!"

config = {
    "apiKey": "AIzaSyB7b_pD9S8nVk1qZVohRvsYtDbqWe9f8XE",
    "authDomain": "game-dev-teacher-webite.firebaseapp.com",
    "projectId": "game-dev-teacher-webite",
    "databaseURL": "https://game-dev-teacher-webite-default-rtdb.firebaseio.com/",
    "storageBucket": "gs://game-dev-teacher-webite.appspot.com/",
    "messagingSenderId": "605556099041",
    "appId": "1:605556099041:web:712a02226e8e8cef3434a0",
    "measurementId": "G-B8PSVYMM0Q",
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()
db = firebase.database()


# emailLogin = input("Enter Email \n")
# passwordLogin = input("Enter Password \n")
# auth.sign_in_with_email_and_password(emailLogin, passwordLogin)

# user = auth.create_user_with_email_and_password(email, password)


@app.route('/login',  methods=['GET', 'POST'])
def login():
    unsucsessful = "Incorrect Username/Password"
    successful = 'Login Sucsessful'
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if(email):
            try:
                user = auth.sign_in_with_email_and_password(email, password)
                session['signedIn'] = True
                resp = make_response(render_template('index.html'))
                resp.set_cookie('signedIn', 'True')
                return render_template('userProfile.html' , signedIn = True, userEmail = email)
            except:        
                return 'Incorrect Username/Password'
    return render_template('login.html')


# Sign Up Method 
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    #Error Messages
    successfulSignUp = "SignUp sucsessful"
    unsuccessfulSignUp = "Invalid Email Address"
    #Get Content from Form
    if request.method == 'POST':
        username = request.form['username']
        emailSignUp = request.form['email_signup']
        passwordSignUp = request.form['password_signup']
        #Checks Email
        if(emailSignUp):
            #Pushes Username to Firebase Database
            data = {"name": username}
            db.child("Username").push(data)
            
            #Adds username to sesson
            session['username'] = username

            # Creates user with email and password
            user = auth.create_user_with_email_and_password(emailSignUp, passwordSignUp)
            auth.send_email_verification(user['idToken'])

            # Return Index Template 
            return render_template('index.html')
        else:
            return render_template('signup.html',  signupBad = True)
    # Return Signup with Unsucsessful Signup
    return render_template('signup.html')

#Logout User
@app.route('/logout')
def logout():
    session['signedIn'] = False
    return redirect(url_for('index'))

@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', signedIn = True)

@app.route('/userProfile')
def userProfile():
    return render_template('userProfile.html')

@app.route('/usernameTest', methods=['GET', 'POST'])
def usernameTest():
    if request.method == 'POST':
        usernameTest = request.form['username']
        print(usernameTest)
        print(session['username'])
        if 'username' in session:
            if session['username'] == usernameTest:
                print("YAY, LOGGED IN!")
            else:   
                print("Incorrect Username")
        else:
            print("Username is not in session")
    return render_template('usernameTest.html')

@app.route('/codeTest')
def codeTest():
    return '<h1>Hello</h1>'

if __name__ == "__main__":
     app.run(debug=True)