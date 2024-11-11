# Syntalix Mail Application

## Overview
This is a Flask-based web application that provides a secure email service with the following features:

1. **User Authentication**: The application allows users to sign up and log in to the system. It supports both employee and regular user accounts.
2. **Secure Email Sending**: Users can compose and send emails with optional attachments. The email content and subject are encrypted using AES encryption before being stored in the MongoDB database.
3. **Encrypted Email Retrieval**: When a user retrieves their emails, the application decrypts the email content and subject, and marks the emails as read.
4. **API Endpoints**: The application exposes a set of RESTful API endpoints for login, signup, sending emails, and fetching emails. These API endpoints can be used by other applications to integrate with the secure email service.
5. **Direct Login**: The application provides a direct login route that accepts email and password as query parameters, allowing for easier integration with other systems.

## Documentation
For detailed documentation, please refer to the provided link:

[Syntalix Mail Application Documentation](https://drive.google.com/drive/folders/1TYcLpsSuZkmALHpjS3NgftBdz0cNix4d?usp=sharing)

## Features
- Secure user authentication with email and password
- Encrypted email storage using AES encryption
- Attachment support for emails
- RESTful API endpoints for integration
- Direct login route for easy integration

## Getting Started
To run the application locally, follow these steps:

1. Clone the repository:
```
git clone https://github.com/your-username/secure-email-app.git
```
2. Install the required dependencies:
```
pip install -r requirements.txt
```
3. Set up the MongoDB Atlas connection:
   - Obtain the connection URI from your MongoDB Atlas account
   - Update the `uri` variable in the `app.py` file with your connection URI
4. Run the Flask application:
```
python app.py
```
5. Access the application in your web browser at `http://localhost:5000`.

## API Endpoints
The application provides the following API endpoints:

| Endpoint | Method | Description |
| --- | --- | --- |
| `/api/login` | POST | Handles user login and returns a session ID. |
| `/api/signup` | POST | Handles user signup. |
| `/api/send_email` | POST | Allows the user to send emails. |
| `/api/fetch_emails` | POST | Retrieves the emails for the logged-in user. |
| `/api/login/direct` | GET | Allows direct login by providing the email and password as query parameters. |

For more details on the API endpoints, please refer to the documentation.

## License
This project is licensed under the [MIT License](LICENSE).
