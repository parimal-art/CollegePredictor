import os
import json
import pandas as pd
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, render_template_string, send_file, abort, redirect, url_for
import logging
import re
import urllib.parse

# Initialize Firebase Admin SDK using environment variable
if not firebase_admin._apps:
    firebase_credentials = json.loads(os.environ.get('FIREBASE_CREDENTIALS').replace('\n', '\n'))
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load and preprocess data
data = pd.read_csv('wbjee_final_clean.xls')

# Handle missing values
data['Seat Type'] = data['Seat Type'].fillna('Unknown')
data['Stream'] = data['Stream'].fillna('Unknown')
data['Program'] = data['Program'].fillna('Unknown')
data['Category'] = data['Category'].fillna('Unknown')

# Normalize columns
for col in ['Program', 'Institute', 'Category', 'Quota', 'Round', 'Seat Type']:
    data[col] = data[col].str.strip().str.title().str.replace('  ', ' ').str.replace('&', 'And')
data['Stream'] = data['Stream'].str.strip().str.replace(r'[./]', '/', regex=True).str.replace('  ', ' ').str.title()
data['Category'] = data['Category'].str.replace('Obc - A', 'Obc-A').str.replace('Obc - B', 'Obc-B')
data['Program'] = data['Program'].str.replace(r'\s*\(.*\)', '', regex=True)
data['Year'] = pd.to_numeric(data['Year'], errors='coerce').fillna(0).astype(int)
data = data.drop_duplicates()

# Verify data
logger.debug(f"Columns: {data.columns.tolist()}")
logger.debug(f"Unique Years: {data['Year'].unique()}")
logger.debug(f"Unique Seat Types: {data['Seat Type'].unique()}")
logger.debug(f"Unique Categories: {data['Category'].unique()}")
logger.debug(f"Unique Programs: {data['Program'].unique()}")
logger.debug(f"Unique Streams: {data['Stream'].unique()}")

# Email validation function (only Gmail addresses)
def is_valid_gmail(email):
    gmail_pattern = r'^[a-zA-Z0-9._%+-]+@gmail\.com$'
    return re.match(gmail_pattern, email) is not None

# Middleware to verify Firebase ID token
def verify_token():
    id_token = request.headers.get('Authorization')
    if not id_token:
        logger.error("No token provided")
        abort(401, description="Unauthorized: No token provided")
    try:
        if id_token.startswith('Bearer '):
            id_token = id_token.split(' ')[1]
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        abort(401, description=f"Unauthorized: Invalid token - {str(e)}")

# HTML templates
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>College Predictor</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" integrity="sha512-DTOQO9RWCH3ppGqcWaEA1BIZOC6xxalwEsw9c2QQeAIftl+Vegovlnee1c9QX4TctnWMn13TZye+giMm8e2LwA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #e0f7fa, #ffffff);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background-color: #4CAF50;
            color: white;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            font-size: 1.25rem;
        }
        .form-container {
            max-width: 600px;
            margin: 2rem auto;
            padding: 2rem;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .form-container:hover {
            transform: translateY(-5px);
        }
        .form-label {
            font-weight: 600;
            color: #333;
            font-size: 1.1rem;
        }
        .form-control {
            border-radius: 10px;
            border: 2px solid #e0e0e0;
            transition: border-color 0.3s;
            font-size: 1rem;
            padding: 0.75rem;
            min-height: 44px;
        }
        .form-control:focus {
            border-color: #4CAF50;
            box-shadow: 0 0 5px rgba(76,175,80,0.3);
        }
        .btn-primary {
            background-color: #4CAF50;
            border-color: #4CAF50;
            border-radius: 10px;
            padding: 0.75rem;
            font-weight: 600;
            font-size: 1rem;
            min-height: 44px;
            transition: background-color 0.3s;
        }
        .btn-primary:hover {
            background-color: #45a049;
        }
        .spinner {
            display: none;
            text-align: center;
            margin-top: 1rem;
        }
        .spinner img {
            width: 30px;
        }
        footer {
            margin-top: auto;
            background-color: #333;
            color: white;
            text-align: center;
            padding: 1.5rem;
            font-size: 0.9rem;
        }
        footer a {
            margin: 0 0.5rem;
            color: #4CAF50;
            text-decoration: none;
        }
        .auth-container {
            display: none;
            max-width: 400px;
            margin: 2rem auto;
            padding: 2rem;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .auth-container.active {
            display: block;
        }
        .error-message {
            color: #dc3545;
            font-size: 0.9rem;
            margin-top: 0.5rem;
            display: none;
        }
        .success-message {
            color: #28a745;
            font-size: 0.9rem;
            margin-top: 0.5rem;
            display: none;
        }
        @media (max-width: 576px) {
            .header {
                font-size: 1rem;
                padding: 1rem;
            }
            .form-container, .auth-container {
                margin: 1rem;
                padding: 1.5rem;
            }
            .form-label {
                font-size: 1rem;
            }
            .form-control {
                font-size: 0.9rem;
                padding: 0.5rem;
            }
            .btn-primary {
                font-size: 0.9rem;
                padding: 0.5rem;
            }
            footer {
                font-size: 0.8rem;
                padding: 1rem;
            }
            footer a {
                display: block;
                margin: 0.5rem 0;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>College Predictor</h1>
        <div id="user-info" style="display: none;">
            <span id="user-email"></span>
            <button class="btn btn-primary" onclick="signOut()">Sign Out</button>
        </div>
    </header>
    <div id="login-form" class="auth-container active">
        <h2 class="text-center mb-4">Login</h2>
        <form id="login-email-form">
            <div class="mb-3">
                <label class="form-label" for="login-email">Email</label>
                <input type="email" id="login-email" class="form-control" required />
                <div id="login-email-error" class="error-message">Please enter a valid Gmail address (e.g., abc@gmail.com).</div>
            </div>
            <div class="mb-3">
                <label class="form-label" for="login-password">Password</label>
                <input type="password" id="login-password" class="form-control" required />
                <div class="form-check mt-2">
                    <input class="form-check-input" type="checkbox" onclick="togglePassword('login-password')" id="show-login-password" />
                    <label class="form-check-label" for="show-login-password">Show Password</label>
                </div>
            </div>
            <button class="btn btn-primary w-100" type="submit">Login</button>
        </form>
        <p class="text-center mt-2">No account? <a href="#" onclick="showSignup()">Sign Up</a></p>
        <p class="text-center mt-2"><a href="#" onclick="showResetPassword()">Forgot Password?</a></p>
    </div>
    <div id="signup-form" class="auth-container">
        <h2 class="text-center mb-4">Sign Up</h2>
        <form id="signup-email-form">
            <div class="mb-3">
                <label class="form-label" for="signup-email">Email</label>
                <input type="email" id="signup-email" class="form-control" required />
                <div id="signup-email-error" class="error-message">Please enter a valid Gmail address (e.g., abc@gmail.com).</div>
                <div id="signup-email-exists-error" class="error-message">User already exists with this email.</div>
            </div>
            <div class="mb-3">
                <label class="form-label" for="signup-password">Password</label>
                <input type="password" id="signup-password" class="form-control" required />
                <div class="form-check mt-2">
                    <input class="form-check-input" type="checkbox" onclick="togglePassword('signup-password')" id="show-signup-password" />
                    <label class="form-check-label" for="show-signup-password">Show Password</label>
                </div>
            </div>
            <button class="btn btn-primary w-100" type="submit">Sign Up</button>
        </form>
        <p class="text-center mt-2">Already have an account? <a href="#" onclick="showLogin()">Login</a></p>
    </div>
    <div id="reset-password-form" class="auth-container">
        <h2 class="text-center mb-4">Reset Password</h2>
        <form id="reset-password-email-form">
            <div class="mb-3">
                <label class="form-label" for="reset-email">Email</label>
                <input type="email" id="reset-email" class="form-control" required />
                <div id="reset-email-error" class="error-message">Please enter a valid Gmail address (e.g., abc@gmail.com).</div>
                <div id="reset-email-success" class="success-message">Password reset email sent. Please check your inbox and spam/junk folder.</div>
            </div>
            <button class="btn btn-primary w-100" type="submit">Send Reset Email</button>
        </form>
        <p class="text-center mt-2"><a href="#" onclick="showLogin()">Back to Login</a></p>
    </div>
    <div id="predictor-form" class="container form-container" style="display: none;">
        <h2 class="text-center mb-4">Find Your College</h2>
        <form id="predict-form" action="/predict" method="POST">
            <div class="mb-3">
                <label class="form-label" for="rank">Your Rank (GMR)</label>
                <input type="number" id="rank" name="rank" class="form-control" required min="1" max="1000000" value="{{ form_data.get('rank', '') }}">
            </div>
            <div class="mb-3">
                <label class="form-label" for="program">Course (Program)</label>
                <select class="form-control" id="program" name="program">
                    <option value="Any" {% if form_data.get('program') == 'Any' %}selected{% endif %}>Any</option>
                    {% for program in programs %}
                        <option value="{{ program }}" {% if form_data.get('program') == program %}selected{% endif %}>{{ program }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="stream">Stream</label>
                <select class="form-control" id="stream" name="stream">
                    <option value="Any" {% if form_data.get('stream') == 'Any' %}selected{% endif %}>Any</option>
                    {% for stream in streams %}
                        <option value="{{ stream }}" {% if form_data.get('stream') == stream %}selected{% endif %}>{{ stream }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="category">Category</label>
                <select class="form-control" id="category" name="category">
                    <option value="Any" {% if form_data.get('category') == 'Any' %}selected{% endif %}>Any</option>
                    {% for category in categories %}
                        <option value="{{ category }}" {% if form_data.get('category') == category %}selected{% endif %}>{{ category }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="quota">Quota</label>
                <select class="form-control" id="quota" name="quota">
                    <option value="Any" {% if form_data.get('quota') == 'Any' %}selected{% endif %}>Any</option>
                    {% for quota in quotas %}
                        <option value="{{ quota }}" {% if form_data.get('quota') == quota %}selected{% endif %}>{{ quota }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="seat_type">Seat Type</label>
                <select class="form-control" id="seat_type" name="seat_type">
                    <option value="Any" {% if form_data.get('seat_type') == 'Any' %}selected{% endif %}>Any</option>
                    {% for seat_type in seat_types %}
                        <option value="{{ seat_type }}" {% if form_data.get('seat_type') == seat_type %}selected{% endif %}>{{ seat_type }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="round">Round</label>
                <select class="form-control" id="round" name="round">
                    <option value="Any" {% if form_data.get('round') == 'Any' %}selected{% endif %}>Any</option>
                    {% for round in rounds %}
                        <option value="{{ round }}" {% if form_data.get('round') == round %}selected{% endif %}>{{ round }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="mb-3">
                <label class="form-label" for="year">Year</label>
                <select class="form-control" id="year" name="year">
                    <option value="Any" {% if form_data.get('year') == 'Any' %}selected{% endif %}>Any</option>
                    {% for year in years %}
                        <option value="{{ year }}" {% if form_data.get('year') == year|string %}selected{% endif %}>{{ year }}</option>
                    {% endfor %}
                </select>
            </div>
            <button type="submit" class="btn btn-primary w-100">Predict Colleges</button>
            <div class="spinner">
                <img src="https://i.giphy.com/media/3oEjI6SIIHBdRxXI40/giphy.webp" alt="Loading">
            </div>
        </form>
    </div>
    <footer>
        © 2025 Parimal Maity, Brainware University (<a href="mailto:parimalmaity852@gmail.com" style="color: #4CAF50;">parimalmaity852@gmail.com</a>)
        <br>
        <a href="https://www.facebook.com/parimal.maity.12382" target="_blank" style="color: #4CAF50;"><i class="fab fa-facebook-f"></i> Facebook</a>
        <a href="https://www.linkedin.com/in/parimal-maity-852241286/" target="_blank" style="color: #4CAF50;"><i class="fab fa-linkedin-in"></i> LinkedIn</a>
        <a href="https://x.com/parimalmaity852?t=IdjWLQPxEXOcnysJEeHJ4g&s=09" target="_blank" style="color: #4CAF50;"><i class="fab fa-x-twitter"></i> X</a>
        <a href="https://www.instagram.com/parimalmaity50/" target="_blank" style="color: #4CAF50;"><i class="fab fa-instagram"></i> Instagram</a>
    </footer>
    <script type="module">
        import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.0/firebase-app.js";
        import {
            getAuth,
            createUserWithEmailAndPassword,
            signInWithEmailAndPassword,
            sendPasswordResetEmail,
            onAuthStateChanged,
            signOut
        } from "https://www.gstatic.com/firebasejs/10.14.0/firebase-auth.js";

        const firebaseConfig = {
            apiKey: "AIzaSyBQL7jInRDHTx08dPqth9eJg-U9OV-86W8",
            authDomain: "collegepredictor-380e7.firebaseapp.com",
            projectId: "collegepredictor-380e7",
            storageBucket: "collegepredictor-380e7.appspot.com",
            messagingSenderId: "508081982289",
            appId: "1:508081982289:web:d83877249ce198769fa170",
            measurementId: "G-NKD70X3EDR"
        };

        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);

        // Store form data globally for pagination
        let formDataCache = {};

        // Toggle Password
        window.togglePassword = function (id) {
            const input = document.getElementById(id);
            input.type = input.type === "password" ? "text" : "password";
        };

        // Form Switch
        window.showLogin = function () {
            document.getElementById('login-form').classList.add('active');
            document.getElementById('signup-form').classList.remove('active');
            document.getElementById('reset-password-form').classList.remove('active');
            document.getElementById('predictor-form').style.display = 'none';
            hideErrors();
        };
        window.showSignup = function () {
            document.getElementById('login-form').classList.remove('active');
            document.getElementById('signup-form').classList.add('active');
            document.getElementById('reset-password-form').classList.remove('active');
            document.getElementById('predictor-form').style.display = 'none';
            hideErrors();
        };
        window.showResetPassword = function () {
            document.getElementById('login-form').classList.remove('active');
            document.getElementById('signup-form').classList.remove('active');
            document.getElementById('reset-password-form').classList.add('active');
            document.getElementById('predictor-form').style.display = 'none';
            hideErrors();
        };
        window.showPredictor = function () {
            document.getElementById('login-form').classList.remove('active');
            document.getElementById('signup-form').classList.remove('active');
            document.getElementById('reset-password-form').classList.remove integrable;
            document.getElementById('predictor-form').style.display = 'block';
            hideErrors();
        };

        // Hide error and success messages
        function hideErrors() {
            document.getElementById('login-email-error').style.display = 'none';
            document.getElementById('signup-email-error').style.display = 'none';
            document.getElementById('signup-email-exists-error').style.display = 'none';
            document.getElementById('reset-email-error').style.display = 'none';
            document.getElementById('reset-email-success').style.display = 'none';
        }

        // Signup
        document.getElementById('signup-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('signup-email').value;
            const password = document.getElementById('signup-password').value;
            const emailError = document.getElementById('signup-email-error');
            const existsError = document.getElementById('signup-email-exists-error');

            if (!isValidGmail(email)) {
                emailError.style.display = 'block';
                return;
            }
            emailError.style.display = 'none';
            existsError.style.display = 'none';

            try {
                await createUserWithEmailAndPassword(auth, email, password);
                await signOut(auth);
                showLogin();
                window.location.href = '/';
            } catch (error) {
                if (error.code === 'auth/email-already-in-use') {
                    existsError.style.display = 'block';
                } else {
                    console.error('Signup failed:', error.message);
                    existsError.textContent = 'Signup failed: ' + error.message;
                    existsError.style.display = 'block';
                }
            }
        });

        // Login
        document.getElementById('login-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const emailError = document.getElementById('login-email-error');

            if (!isValidGmail(email)) {
                emailError.style.display = 'block';
                return;
            }
            emailError.style.display = 'none';

            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                setTimeout(() => {
                    window.location.href = '/predictor';
                }, 100);
                updateUserInfo(userCredential.user);
            } catch (error) {
                console.error('Login failed:', error.message);
                if (error.code === 'auth/invalid-credential' || error.code === 'auth/wrong-password' || error.code === 'auth/user-not-found') {
                    emailError.textContent = 'Invalid username or password';
                    emailError.style.display = 'block';
                } else {
                    emailError.textContent = 'Login failed: ' + error.message;
                    emailError.style.display = 'block';
                }
            }
        });

        // Reset Password
        document.getElementById('reset-password-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('reset-email').value;
            const emailError = document.getElementById('reset-email-error');
            const successMessage = document.getElementById('reset-email-success');
            let attempt = 0;
            const maxAttempts = 2;

            if (!isValidGmail(email)) {
                emailError.style.display = 'block';
                successMessage.style.display = 'none';
                return;
            }
            emailError.style.display = 'none';
            successMessage.style.display = 'none';

            async function sendResetEmail() {
                try {
                    console.log(`Attempt ${attempt + 1} to send reset email to: ${email} at ${new Date().toISOString()}`);
                    await sendPasswordResetEmail(auth, email);
                    console.log(`Reset email request successful for ${email} at ${new Date().toISOString()}`);
                    successMessage.style.display = 'block';
                    setTimeout(() => {
                        showLogin();
                        hideErrors();
                    }, 3000);
                } catch (error) {
                    console.error(`Reset password failed for ${email} at ${new Date().toISOString()}:`, error.message, error.code);
                    if (attempt < maxAttempts - 1 && error.code !== 'auth/user-not-found' && error.code !== 'auth/too-many-requests') {
                        attempt++;
                        await new Promise(resolve => setTimeout(resolve, 2000));
                        await sendResetEmail();
                    } else {
                        emailError.textContent = error.code === 'auth/user-not-found' ? 'No user found with this email.' :
                                               error.code === 'auth/too-many-requests' ? 'Too many requests. Try again later.' :
                                               'Reset failed: Unable to send email. Check your connection or Firebase settings.';
                        emailError.style.display = 'block';
                    }
                }
            }

            sendResetEmail();
        });

        // Sign Out
        window.signOut = function () {
            signOut(auth).then(() => {
                window.location.href = '/';
            }).catch((error) => {
                console.error('Sign out failed:', error.message);
                alert('Sign out failed: ' + error.message);
            });
        };

喧

        // Update User Info
        function updateUserInfo(user) {
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('user-email').textContent = user.email;
        }

        // Auth State Monitor
        onAuthStateChanged(auth, (user) => {
            if (user) {
                console.log("User signed in:", user.email);
                updateUserInfo(user);
                if (window.location.pathname === '/predictor') {
                    showPredictor();
                } else {
                    showLogin();
                }
            } else {
                console.log("No user signed in.");
                showLogin();
            }
        });

        // Predict form submission
        document.getElementById('predict-form').addEventListener('submit', async function(e) {
            e.preventDefault();
            document.querySelector('.spinner').style.display = 'block';
            document.querySelector('.btn-primary').disabled = true;

            try {
                const idToken = await auth.currentUser.getIdToken(true);
                const form = document.getElementById('predict-form');
                const formData = new FormData(form);
                formDataCache = Object.fromEntries(formData.entries());
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${idToken}`
                    },
                    body: formData
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }

                const html = await response.text();
                document.open();
                document.write(html);
                document.close();
            } catch (error) {
                console.error('Error:', error.message);
                alert('Error: ' + error.message);
            } finally {
                document.querySelector('.spinner').style.display = 'none';
                document.querySelector('.btn-primary').disabled = false;
            }
        });

        // Gmail validation function
        function isValidGmail(email) {
            const gmailPattern = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
            return gmailPattern.test(email);
        }

        showLogin();
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

RESULTS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prediction Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" integrity="sha512-DTOQO9RWCH3ppGqcWaEA1BIZOC6xxalwEsw9c2QQeAIftl+Vegovlnee1c9QX4TctnWMn13TZye+giMm8e2LwA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #e0f7fa, #ffffff);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background-color: #4CAF50;
            color: white;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            font-size: 1.25rem;
        }
        .results-container {
            max-width: 1200px;
            margin: 2rem auto;
            padding: 2rem;
            background: white;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .results-container:hover {
            transform: translateY(-5px);
        }
        .table-responsive {
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }
        .table {
            border-radius: 10px;
            overflow: hidden;
            font-size: 1rem;
            min-width: 800px;
        }
        .table th {
            background-color: #4CAF50;
            color: white;
            position: sticky;
            top: 0;
            z-index: 1;
            padding: 0.75rem;
        }
        .table td {
            padding: 0.75rem;
            vertical-align: middle;
        }
        .table tbody tr:hover {
            background-color: #f1f8e9;
        }
        .btn-primary, .btn-success {
            background-color: #4CAF50;
            border-color: #4CAF50;
            border-radius: 10px;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            min-height: 44px;
            margin: 0.5rem;
            transition: background-color 0.3s;
        }
        .btn-primary:hover, .btn-success:hover {
            background-color: #45a049;
        }
        .alert {
            border-radius: 10px;
            font-size: 1rem;
            padding: 1rem;
        }
        .pagination {
            margin-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        footer {
            margin-top: auto;
            background-color: #333;
            color: white;
            text-align: center;
            padding: 1.5rem;
            font-size: 0.9rem;
        }
        footer a {
            margin: 0 0.5rem;
            color: #4CAF50;
            text-decoration: none;
        }
        @media (max-width: 576px) {
            .header {
                font-size: 1rem;
                padding: 1rem;
            }
            .results-container {
                margin: 1rem;
                padding: 1.5rem;
            }
            .table {
                font-size: 0.85rem;
            }
            .table th, .table td {
                padding: 0.5rem;
            }
            .btn-primary, .btn-success {
                font-size: 0.9rem;
                padding: 0.5rem 1rem;
                margin: 0.25rem;
            }
            .alert {
                font-size: 0.9rem;
                padding: 0.75rem;
            }
            footer {
                font-size: 0.8rem;
                padding: 1rem;
            }
            footer a {
                display: block;
                margin: 0.5rem 0;
            }
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>College Predictor</h1>
        <div id="user-info" style="display: none;">
            <span id="user-email"></span>
            <button class="btn btn-primary" onclick="signOut()">Sign Out</button>
        </div>
    </header>
    <div class="container results-container">
        <h2 class="text-center mb-4">Colleges for Rank {{ rank }}</h2>
        {% if low_rank_message %}
            <div class="alert alert-info text-center">
                {{ low_rank_message }}
            </div>
        {% endif %}
        {% if min_rank_message %}
            <div class="alert alert-warning text-center">
                {{ min_rank_message }}
            </div>
        {% endif %}
        {% if results %}
            <div class="table-responsive">
                <table class="table table-bordered table-striped table-hover">
                    <thead>
                        <tr>
                            <th>Institute</th>
                            <th>Program</th>
                            <th>Round</th>
                            <th>Category</th>
                            <th>Quota</th>
                            <th>Seat Type</th>
                            <th>Opening Rank</th>
                            <th>Closing Rank</th>
                            <th>Year</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for result in results %}
                            <tr>
                                <td>{{ result['Institute'] }}</td>
                                <td>{{ result['Program'] }}</td>
                                <td>{{ result['Round'] }}</td>
                                <td>{{ result['Category'] }}</td>
                                <td>{{ result['Quota'] }}</td>
                                <td>{{ result['Seat Type'] }}</td>
                                <td>{{ result['Opening Rank'] }}</td>
                                <td>{{ result['Closing Rank'] }}</td>
                                <td>{{ result['Year'] }}</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            <div class="pagination">
                <div>
                    {% if page > 1 %}
                        <button class="btn btn-primary" onclick="navigatePage({{ page - 1 }})">Previous</button>
                    {% endif %}
                    {% if has_next %}
                        <button class="btn btn-primary" onclick="navigatePage({{ page + 1 }})">Next</button>
                    {% endif %}
                </div>
                <div>
                    <button class="btn btn-primary" onclick="downloadResults()">Download All Results</button>
                </div>
            </div>
            <p class="mt-2 text-center">Page {{ page }} | Showing {{ results|length }} of {{ total_results }} results</p>
        {% else %}
            <div class="alert alert-warning text-center">
                No colleges found for your rank and filters. Try relaxing filters like Stream, Program, Category, or Year.
            </div>
        {% endif %}
        <div class="text-center mt-4">
            <a href="/predictor?rank={{ form_data.get('rank', '')|urlencode }}{% for key, value in form_data.items() if key != 'rank' %}&{{ key }}={{ value|urlencode }}{% endfor %}" class="btn btn-success">Back to Home</a>
        </div>
    </div>
    <footer>
        © 2025 Parimal Maity, Brainware University (<a href="mailto:parimalmaity852@gmail.com" style="color: #4CAF50;">parimalmaity852@gmail.com</a>)
        <br>
        <a href="https://www.facebook.com/parimal.maity.12382" target="_blank" style="color: #4CAF50;"><i class="fab fa-facebook-f"></i> Facebook</a>
        <a href="https://www.linkedin.com/in/parimal-maity-852241286/" target="_blank" style="color: #4CAF50;"><i class="fab fa-linkedin-in"></i> LinkedIn</a>
        <a href="https://x.com/parimalmaity852?t=IdjWLQPxEXOcnysJEeHJ4g&s=09" target="_blank" style="color: #4CAF50;"><i class="fab fa-x-twitter"></i> X</a>
        <a href="https://www.instagram.com/parimalmaity50/" target="_blank" style="color: #4CAF50;"><i class="fab fa-instagram"></i> Instagram</a>
    </footer>
    <script type="module">
        import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.0/firebase-app.js";
        import {
            getAuth,
            signOut,
            onAuthStateChanged
        } from "https://www.gstatic.com/firebasejs/10.14.0/firebase-auth.js";

        const firebaseConfig = {
            apiKey: "AIzaSyBQL7jInRDHTx08dPqth9eJg-U9OV-86W8",
            authDomain: "collegepredictor-380e7.firebaseapp.com",
            projectId: "collegepredictor-380e7",
            storageBucket: "collegepredictor-380e7.appspot.com",
            messagingSenderId: "508081982289",
            appId: "1:508081982289:web:d83877249ce198769fa170",
            measurementId: "G-NKD70X3EDR"
        };

        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);

        // Form data cache
        const formDataCache = {{ form_data|tojson }};

        // Sign Out
        window.signOut = function () {
            signOut(auth).then(() => {
                window.location.href = '/';
            }).catch((error) => {
                console.error('Sign out failed:', error.message);
                alert('Sign out failed: ' + error.message);
            });
        };

        // Update User Info
        function updateUserInfo(user) {
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('user-email').textContent = user.email;
        }

        // Navigate Page
        window.navigatePage = async function(page) {
            try {
                const idToken = await auth.currentUser.getIdToken(true);
                console.log('Navigating to page:', page, 'Form data:', formDataCache);
                const formData = new FormData();
                for (const [key, value] of Object.entries(formDataCache)) {
                    if (key !== 'page') {
                        formData.append(key, value);
                    }
                }
                formData.append('page', page);
                const response = await fetch('/predict', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${idToken}`
                    },
                    body: formData
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }

                const html = await response.text();
                document.open();
                document.write(html);
                document.close();
            } catch (error) {
                console.error('Navigation error:', error.message);
                alert('Error navigating page: ' + error.message);
            }
        };

        // Download Results
        window.downloadResults = async function() {
            try {
                const idToken = await auth.currentUser.getIdToken(true);
                const response = await fetch('/download', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${idToken}`
                    }
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }

                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'college_results.csv';
                document.body.appendChild(a);
                a.click();
                a.remove();
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Download error:', error.message);
                alert('Error downloading results: ' + error.message);
            }
        };

        // Auth State Monitor
        onAuthStateChanged(auth, (user) => {
            if (user) {
                console.log("User signed in:", user.email);
                updateUserInfo(user);
            } else {
                console.log("No user signed in.");
                window.location.href = '/';
            }
        });
    </script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

@app.route('/')
def home():
    programs = sorted([x for x in data['Program'].unique() if pd.notna(x) and x != 'Unknown'])
    streams = sorted([x for x in data['Stream'].unique() if pd.notna(x) and x != 'Unknown'])
    categories = sorted([x for x in data['Category'].unique() if pd.notna(x) and x != 'Unknown'])
    quotas = sorted([x for x in data['Quota'].unique() if pd.notna(x)])
    seat_types = sorted([x for x in data['Seat Type'].unique() if pd.notna(x) and x != 'Unknown'])
    rounds = sorted([x for x in data['Round'].unique() if pd.notna(x)])
    years = sorted([x for x in data['Year'].unique() if x != 0])
    form_data = {k: urllib.parse.unquote(v) for k, v in request.args.items() if k in ['rank', 'program', 'stream', 'category', 'quota', 'seat_type', 'round', 'year']}
    return render_template_string(INDEX_HTML, programs=programs, streams=streams, categories=categories,
                                 quotas=quotas, seat_types=seat_types, rounds=rounds, years=years, form_data=form_data)

@app.route('/predictor')
def predictor():
    programs = sorted([x for x in data['Program'].unique() if pd.notna(x) and x != 'Unknown'])
    streams = sorted([x for x in data['Stream'].unique() if pd.notna(x) and x != 'Unknown'])
    categories = sorted([x for x in data['Category'].unique() if pd.notna(x) and x != 'Unknown'])
    quotas = sorted([x for x in data['Quota'].unique() if pd.notna(x)])
    seat_types = sorted([x for x in data['Seat Type'].unique() if pd.notna(x) and x != 'Unknown'])
    rounds = sorted([x for x in data['Round'].unique() if pd.notna(x)])
    years = sorted([x for x in data['Year'].unique() if x != 0])
    form_data = {k: urllib.parse.unquote(v) for k, v in request.args.items() if k in ['rank', 'program', 'stream', 'category', 'quota', 'seat_type', 'round', 'year']}
    return render_template_string(INDEX_HTML, programs=programs, streams=streams, categories=categories,
                                 quotas=quotas, seat_types=seat_types, rounds=rounds, years=years, form_data=form_data)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        decoded_token = verify_token()
        logger.debug(f"Authenticated user: {decoded_token.get('email')}")
        form_data = request.form.to_dict()
        rank = int(form_data.get('rank', '0'))
        page = int(form_data.get('page', '1'))
        per_page = 20
        program = form_data.get('program', 'Any')
        stream = form_data.get('stream', 'Any')
        category = form_data.get('category', 'Any')
        quota = form_data.get('quota', 'Any')
        seat_type = form_data.get('seat_type', 'Any')
        round = form_data.get('round', 'Any')
        year = form_data.get('year', 'Any')
        if not 1 <= rank <= 1000000:
            raise ValueError("Rank must be between 1 and 1,000,000")
        year_int = int(year) if year != 'Any' and year.isdigit() else None
        logger.debug(f"Input: rank={rank}, program={program}, stream={stream}, category={category}, quota={quota}, seat_type={seat_type}, round={round}, year={year}, page={page}")
        filtered_data = data.copy()
        low_rank_message = None
        min_rank_message = None
        temp_data = filtered_data.copy()
        if program != 'Any':
            logger.debug(f"Applying program filter: {program}")
            temp_data = temp_data[temp_data['Program'] == program]
            logger.debug(f"After program filter, rows: {len(temp_data)}")
        if stream != 'Any':
            logger.debug(f"Applying stream filter: {stream}")
            temp_data = temp_data[temp_data['Stream'] == stream]
            logger.debug(f"After stream filter, rows: {len(temp_data)}")
        if category != 'Any':
            logger.debug(f"Applying category filter: {category}")
            temp_data = temp_data[temp_data['Category'] == category]
            logger.debug(f"After category filter, rows: {len(temp_data)}")
        if quota != 'Any':
            logger.debug(f"Applying quota filter: {quota}")
            temp_data = temp_data[temp_data['Quota'] == quota]
            logger.debug(f"After quota filter, rows: {len(temp_data)}")
        if seat_type != 'Any':
            logger.debug(f"Applying seat_type filter: {seat_type}")
            temp_data = temp_data[temp_data['Seat Type'] == seat_type]
            logger.debug(f"After seat_type filter, rows: {len(temp_data)}")
        if round != 'Any':
            logger.debug(f"Applying round filter: {round}")
            temp_data = temp_data[temp_data['Round'] == round]
            logger.debug(f"After round filter, rows: {len(temp_data)}")
        if year != 'Any':
            logger.debug(f"Applying year filter: {year}")
            temp_data = temp_data[temp_data['Year'] == int(year)]
            logger.debug(f"After year filter, rows: {len(temp_data)}")
        if temp_data.empty or 'Opening Rank' not in temp_data.columns:
            min_rank_message = "No colleges found for these filters. Try relaxing filters like Stream, Program, Category, or Year."
            if stream != 'Any':
                logger.debug(f"Retrying without stream filter: {stream}")
                temp_data = filtered_data.copy()
                if program != 'Any':
                    temp_data = temp_data[temp_data['Program'] == program]
                if category != 'Any':
                    temp_data = temp_data[temp_data['Category'] == category]
                if quota != 'Any':
                    temp_data = temp_data[temp_data['Quota'] == quota]
                if seat_type != 'Any':
                    temp_data = temp_data[temp_data['Seat Type'] == seat_type]
                if round != 'Any':
                    temp_data = temp_data[temp_data['Round'] == round]
                if year != 'Any':
                    temp_data = temp_data[temp_data['Year'] == int(year)]
                min_rank_message += f" Showing results without Stream filter."
            filtered_data = pd.DataFrame(columns=data.columns) if temp_data.empty else temp_data
            logger.debug("No results after applying filters or missing 'Opening Rank' column")
        else:
            min_opening_rank = temp_data['Opening Rank'].min()
            max_opening_rank = temp_data['Opening Rank'].max()
            logger.debug(f"Min opening rank: {min_opening_rank}, Max opening rank: {max_opening_rank}")
            filtered_data = temp_data[
                (temp_data['Opening Rank'] <= rank) &
                (temp_data['Closing Rank'] >= rank)
            ]
            if filtered_data.empty:
                min_rank_message = f"No colleges found for rank {rank}. Showing colleges with opening ranks above or below your rank."
                filtered_data = temp_data.copy()
                filtered_data['Rank_Diff'] = abs(filtered_data['Opening Rank'] - rank)
                filtered_data = filtered_data.sort_values('Rank_Diff').drop(columns=['Rank_Diff'])
                logger.debug(f"Showing {len(filtered_data)} colleges with ranks above/below")
        if not filtered_data.empty and not min_rank_message and len(filtered_data) < 10:
            low_rank_message = f"Showing additional colleges to provide more options."
            filtered_data = temp_data.copy()
            filtered_data['Rank_Diff'] = abs(filtered_data['Opening Rank'] - rank)
            filtered_data = filtered_data.sort_values('Rank_Diff').drop(columns=['Rank_Diff'])
            logger.debug(f"Expanded results, rows: {len(filtered_data)}")
        if min_rank_message or low_rank_message:
            filtered_data = filtered_data.sort_values('Opening Rank')
        else:
            filtered_data = filtered_data.sort_values('Closing Rank')
        if not filtered_data.empty:
            filtered_data.to_csv('results.csv', index=False)
        else:
            logger.warning("No data to save to results.csv")
        total_results = len(filtered_data)
        start = (page - 1) * per_page
        end = min(start + per_page, total_results)
        paginated_results = filtered_data.iloc[start:end][['Institute', 'Program', 'Round', 'Category', 'Quota', 'Seat Type', 'Opening Rank', 'Closing Rank', 'Year']].to_dict('records')
        has_next = end < total_results
        form_data['page'] = str(page)  # Ensure page is included in form_data for pagination
        logger.debug(f"Rendering page {page} with {len(paginated_results)} results, total={total_results}, has_next={has_next}")
        return render_template_string(RESULTS_HTML, results=paginated_results, rank=rank, page=page, has_next=has_next,
                                     total_results=total_results, form_data=form_data, low_rank_message=low_rank_message,
                                     min_rank_message=min_rank_message)
    except ValueError as ve:
        logger.error(f"Validation error in predict: {str(ve)}")
        abort(400, description=f"Validation Error: {str(ve)}")
    except Exception as e:
        logger.error(f"Error in predict: {str(e)}")
        abort(500, description=f"Error: {str(e)}")

@app.route('/download')
def download():
    try:
        verify_token()
        if os.path.exists('results.csv'):
            return send_file('results.csv', as_attachment=True, download_name='college_results.csv')
        else:
            logger.error("No results file found")
            abort(404, description="No results to download. Please generate results first.")
    except Exception as e:
        logger.error(f"Error in download: {str(e)}")
        abort(500, description=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)