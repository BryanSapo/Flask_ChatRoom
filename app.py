from flask import Flask, render_template, redirect, url_for, flash, request, session,jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyrebase
from datetime import datetime
import os
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['DEBUG'] = True
@app.route('/')
def landing():
    return render_template('landing.html')
@app.errorhandler(Exception)
def handle_exception(e):
    print(str(e), file=sys.stderr)
    return str(e), 500
# Firebase configuration
firebase_config = {
    "apiKey": "AIzaSyBRw-lOvRw0R7c6GgyWWFRACdzgYKYn7qI",
    "authDomain": "flask-chat-room.firebaseapp.com",
    "databaseURL": "https://flask-chat-room-default-rtdb.firebaseio.com",
    "projectId": "flask-chat-room",
    "storageBucket": "flask-chat-room.appspot.com",
    "messagingSenderId": "60784813085",
    "appId": "1:60784813085:web:54594626a95baa37a992f4"
}

firebase = pyrebase.initialize_app(firebase_config)
db = firebase.database()
auth = firebase.auth()

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.session_protection = None
class User(UserMixin):
    def __init__(self, uid, username, is_admin=False):
        self.id = uid
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    user_data = db.child("users").child(user_id).get().val()
    if user_data:
        return User(user_id, user_data['username'], user_data.get('is_admin', False))
    return None

@app.route('/chat')
@login_required
def chat():
    if not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    messages = db.child("messages").get().val()
    if messages:
        messages = [{'id': k, **v} for k, v in messages.items()]
        messages.sort(key=lambda x: x['timestamp'])
    else:
        messages = []
    return render_template('chat.html', messages=messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            user_data = db.child("users").child(user['localId']).get().val()
            login_user(User(user['localId'], user_data['username'], user_data.get('is_admin', False)))
            return redirect(url_for('chat',_external=True))
        except:
            flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        try:
            user = auth.create_user_with_email_and_password(email, password)
            is_admin = (username == 'Teacher')
            db.child("users").child(user['localId']).set({
                "username": username,
                "email": email,
                "is_admin": is_admin
            })
            flash('Account created successfully')
            return redirect(url_for('login',_external=True))
        except:
            flash('Registration failed')
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login',_external=True))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form.get('content')
    if content:
        db.child("messages").push({
            "content": content,
            "user_id": current_user.id,
            "username": current_user.username,
            "timestamp": datetime.utcnow().isoformat()
        })
    return redirect(url_for('chat',_external=True))

@app.route('/delete_message/<message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    if current_user.is_admin:
        db.child("messages").child(message_id).remove()
        flash('Message deleted successfully')
    return redirect(url_for('chat',_external=True))

@app.route('/users')
@login_required
def users():
    if current_user.is_admin:
        users = db.child("users").get().val()
        if users:
            users = [{'id': k, **v} for k, v in users.items()]
        else:
            users = []
        return render_template('users.html', users=users)
    return redirect(url_for('chat',_external=True))

@app.route('/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.is_admin:
        user_data = db.child("users").child(user_id).get().val()
        if user_data and not user_data.get('is_admin', False):
            db.child("users").child(user_id).remove()
            flash('User deleted successfully')
        else:
            flash('Cannot delete admin user')
    return redirect(url_for('users',_external=True))

# if __name__ == '__main__':
#     app.run(debug=True)
if __name__ == '__main__':
    app.run()