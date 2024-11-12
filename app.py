from flask import Flask, render_template, request, redirect, session, jsonify
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import datetime
import os
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB Atlas connection
uri = "mongodb+srv://soujashban:hrVGtkBurivaUCbN@cluster0.hykpe.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri, server_api=ServerApi('1'))
db = client.get_database('users')
users = db.get_collection('users')
emails = db.get_collection('emails')  # New collection for storing emails

# Configure upload folder
UPLOAD_FOLDER = 'uploads'  # Specify your upload folder
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create upload folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def encrypt_message(message, key):
    iv = os.urandom(16)  # Generate a random IV
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_message(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data.encode('utf-8'))
    iv = encrypted_data[:16]
    actual_encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return decrypted_data.decode()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if request.form['action'] == 'login':
            # Login logic
            email = request.form['username']
            password = request.form['password']
            user = users.find_one({'email': email})
            if user and check_password_hash(user['password'],password):
                if email.endswith('@syntalix.employee'):
                    employee_id = request.form.get('employee-id')
                    if employee_id == user.get('employee_id'):
                        session['user'] = user['email']
                        session['type'] = 'employee'
                        session['employee_id'] = user['employee_id']
                        return redirect('/dashboard')
                    else:
                        error = 'Invalid employee ID'
                else:
                    session['user'] = user['email']
                    session['type'] = 'user'
                    return redirect('/dashboard')
            else:
                error = 'Invalid email or password'
        elif request.form['action'] == 'signup':
            # Signup logic
            username = request.form['username']
            type = request.form['type']
            mail_name = request.form['mail_name']
            password = generate_password_hash(request.form['password'])
            if mail_name == 'admin':
                error = 'Mail name not allowed'
            elif users.find_one({'email': f"{mail_name}@syntalix.{type}"}):
                error = 'Email already registered'
            else:
                if type == 'employee':
                    employee_id = f'SYN{users.count_documents({}):05}LX'
                    users.insert_one({
                        'username': username,
                        'type': type,
                        'email': f"{mail_name}@syntalix.{type}",
                        'password': password,
                        'employee_id': employee_id
                    })
                else:
                    users.insert_one({
                        'username': username,
                        'type': type,
                        'email': f"{mail_name}@syntalix.{type}",
                        'password': password
                    })
                session['user'] = f"{mail_name}@syntalix.{type}"
                session['type'] = type
                return redirect('/dashboard')
    return render_template('login.html', error=error if 'error' in locals() else None)

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html')
    return redirect('/')

@app.route('/send_email', methods=['POST'])
def send_email():
    if 'user' in session:
        try:
            data = request.form
            attachments = []

            # Process attachments
            for file in request.files.getlist('attachments'):
                if file:
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
                    attachments.append({'filename': filename, 'path': filepath})

            # Generate a random AES key for this email
            key = os.urandom(32)  # AES-256 key

            # Encrypt the email content and subject
            encrypted_content = encrypt_message(data['content'], key)
            encrypted_subject = encrypt_message(data['subject'], key)

            email = {
                'sender': session['user'],
                'receiver': data['to'],
                'subject': encrypted_subject,
                'content': encrypted_content,
                'attachments': attachments,
                'timestamp': datetime.datetime.now(),
                'read': False,
                'key': base64.b64encode(key).decode('utf-8')  # Store the key securely (you may want to encrypt this key)
            }

            # Insert the email into MongoDB
            emails.insert_one(email)
            return jsonify({'success': True, 'message': 'Email sent successfully'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500
    return jsonify({'success': False, 'message': 'Not logged in'}), 401

@app.route('/fetch_emails')
def fetch_emails():
    if 'user' in session:
        user_email = session['user']
        email_list = list(emails.find({'receiver': user_email}).sort('timestamp', -1))

        processed_emails = []
        for email in email_list:
            try:
                # Decrypt subject and content using the stored key
                key = base64.b64decode(email['key'].encode('utf-8'))
                decrypted_subject = decrypt_message(email['subject'], key)
                decrypted_content = decrypt_message(email['content'], key)
                print((email['read']))
                # Update the email as read in the database
                processed_emails.append({
                    'email_id': str(email['_id']),
                    'sender': email['sender'],
                    'receiver': email['receiver'],
                    'subject': decrypted_subject,
                    'content': decrypted_content,
                    'attachments': email.get('attachments', []),
                    'timestamp': email['timestamp'],
                    'read': email['read'], 
                })
            except Exception as e:
                # Handle decryption errors if needed
                print(f"Error decrypting email {email['_id']}: {e}")

        return jsonify(processed_emails)
    return jsonify([])


@app.route('/mark_as_read/<email_id>', methods=['POST'])
def mark_as_read(email_id):
    try:
        print(email_id)
        result = emails.update_one(
            {'_id': ObjectId(email_id)},
            {'$set': {'read': True}}
        )
        if result.modified_count == 1:
            print(f"Email {email_id} marked as read.")
        else:
            print(f"Email {email_id} not found or already marked as read.")
        return '', 204
    except Exception as e:
        print(f"Error marking email as read: {e}")
        return 'Failed to mark as read', 500
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data['email']
    password = data['password']
    user = users.find_one({'email': email, 'password': password})
    
    if user and check_password_hash(user['password'],password):
        session_id = str(ObjectId())  # Generate a unique session ID
        session['user'] = email
        session['session_id'] = session_id  # Store the session ID in the server session
        
        return jsonify({'success': True, 'session_id': session_id}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()  # Expecting JSON payload with 'username', 'email', 'password', 'type'
    
    username = data.get('username')
    email = data.get('email')
    password = generate_password_hash(data.get('password'))
    user_type = data.get('type')
    
    if not username or not email or not password or not user_type:
        return jsonify({'success': False, 'message': 'All fields (username, email, password, type) are required'}), 400
    
    if '@syntalix.employee' in email and user_type != 'employee':
        return jsonify({'success': False, 'message': 'Invalid email domain for non-employee type'}), 400

    if users.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already registered'}), 400

    # If user is of type 'employee', generate an employee ID
    if user_type == 'employee':
        employee_id = f'SYN{users.count_documents({})+1:05}LX'  # Generate a unique employee ID
        users.insert_one({
            'username': username,
            'email': email,
            'password': password,
            'type': user_type,
            'employee_id': employee_id
        })
    else:
        users.insert_one({
            'username': username,
            'email': email,
            'password': password,
            'type': user_type
        })
    
    return jsonify({'success': True, 'message': 'Signup successful'})

@app.route('/api/send_email', methods=['POST'])
def send_email_handler():
    data = request.get_json()

    # Ensure that 'to', 'subject', 'content' are in the request data
    if not all(key in data for key in ('to', 'subject', 'content')):
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if 'user' exists in the session (i.e., the user is logged in)
    if 'user' not in session:
        # If not logged in, attempt to log in using the provided email and password
        email = data.get('email')  # Assuming email is provided in the body
        password = data.get('password')  # Assuming password is provided in the body

        if not email or not password:
            return jsonify({'message': 'Email and password are required for login'}), 400

        # Try to log the user in
        user = users.find_one({"email": email})
        if user and check_password_hash(user["password"],password):
            session['user'] = email  # Store user in the session
            print(f"User {email} logged in successfully!")
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

    # Now that the user is logged in, proceed with sending the email
    try:
        # Process the email content
        attachments = []
        for file in request.files.getlist('attachments'):
            if file:
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                attachments.append({'filename': filename, 'path': filepath})

        # Generate a random AES key for encryption
        key = os.urandom(32)  # AES-256 key

        # Encrypt the email content and subject
        encrypted_content = encrypt_message(data['content'], key)
        encrypted_subject = encrypt_message(data['subject'], key)

        email = {
            'sender': session['user'],
            'receiver': data['to'],
            'subject': encrypted_subject,
            'content': encrypted_content,
            'attachments': attachments,
            'timestamp': datetime.datetime.now(),
            'read': False,
            'key': base64.b64encode(key).decode('utf-8')  # Store the key securely
        }

        # Insert the email into MongoDB
        emails.insert_one(email)
        return jsonify({'message': 'Email sent successfully'})

    except Exception as e:
        return jsonify({'message': f"Failed to send email: {str(e)}"}), 500


@app.route('/api/fetch_emails', methods=['POST'])
def fetch_emails_handler():
    data = request.get_json()

    # Check for email and password in the request for login purposes
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required for login'}), 400

    # Check if the user is already logged in
    if 'user' not in session:
        # Attempt to log the user in
        user = users.find_one({"email": email})
        if user and check_password_hash(user['password'],password):
            session['user'] = email  # Store the user in the session
            print(f"User {email} logged in successfully!")
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

    # Now that the user is logged in, proceed to fetch emails
    try:
        user_email = session['user']
        email_list = list(emails.find({'receiver': user_email}).sort('timestamp', -1))

        processed_emails = []
        for email in email_list:
            try:
                # Decrypt subject and content using the stored key
                key = base64.b64decode(email['key'].encode('utf-8'))
                decrypted_subject = decrypt_message(email['subject'], key)
                decrypted_content = decrypt_message(email['content'], key)

                # Mark the email as read in the database
                emails.update_one(
                    {'_id': email['_id']},
                    {'$set': {'read': True}}
                )

                processed_emails.append({
                    'email_id': str(email['_id']),
                    'sender': email['sender'],
                    'receiver': email['receiver'],
                    'subject': decrypted_subject,
                    'content': decrypted_content,
                    'attachments': email.get('attachments', []),
                    'timestamp': email['timestamp'],
                    'read': True,  # Mark as read since it's been accessed
                })
            except Exception as e:
                print(f"Error decrypting email {email['_id']}: {e}")

        return jsonify(processed_emails)

    except Exception as e:
        return jsonify({'message': f"Failed to fetch emails: {str(e)}"}), 500
    

@app.route('/api/login/direct', methods=['GET'])
def direct_login():
    # Extract email and password from the URL query parameters
    email = request.args.get('email')
    password = request.args.get('password')
    
    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    # Find user by email and password
    user = users.find_one({'email': email})

    if user and check_password_hash(user['password'],password):
        # Use MongoDB ObjectId as the session ID
        session_id = str(user['_id'])
        
        # Store the session details (email, session ID, etc.) in the session
        session['user'] = user['email']
        session['session_id'] = session_id
        
        # Redirect to the dashboard after successful login
        return redirect('/dashboard')
    else:
        # If login fails, return an error message
        return jsonify({"message": "Invalid email or password"}), 401




if __name__ == '__main__':
    app.run(debug=True)
