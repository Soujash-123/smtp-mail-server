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
            user = users.find_one({'email': email, 'password': password})
            if user:
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
            password = request.form['password']
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

                # Update the email as read in the database
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
                    'read': True,  # Set to True since we just marked it as read
                })
            except Exception as e:
                # Handle decryption errors if needed
                print(f"Error decrypting email {email['_id']}: {e}")

        return jsonify(processed_emails)
    return jsonify([])


@app.route('/mark_as_read', methods=['POST'])
def mark_as_read():
    if 'user' in session:
        try:
            email_id = request.json.get('email_id')

            if not email_id:
                return jsonify({'success': False, 'message': 'No email_id provided'}), 400

            try:
                email_obj_id = ObjectId(email_id)
            except Exception:
                return jsonify({'success': False, 'message': 'Invalid email_id format'}), 400

            result = emails.update_one(
                {'_id': email_obj_id},
                {'$set': {'read': True}}
            )

            if result.matched_count == 0:
                return jsonify({'success': False, 'message': 'Email not found'}), 404

            return jsonify({'success': True, 'message': 'Email marked as read'}), 200

        except Exception as e:
            print(f"Error in /mark_as_read: {e}")
            return jsonify({'success': False, 'message': 'Server error'}), 500

    return jsonify({'success': False, 'message': 'Not logged in'}), 401

if __name__ == '__main__':
    app.run(debug=True)
