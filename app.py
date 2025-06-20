import os
import time
import pytz
from datetime import datetime
os.environ['TZ'] = 'UTC'
try:
    time.tzset()
except AttributeError:
    pass

import json
import pandas as pd
import firebase_admin
from firebase_admin import credentials, auth
from flask import Flask, request, render_template_string, send_file, abort
import logging
import re
import urllib.parse
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Firebase Admin SDK
if not firebase_admin._apps:
    firebase_credentials = os.environ.get('FIREBASE_CREDENTIALS')
    if firebase_credentials:
        try:
            cred = credentials.Certificate(json.loads(firebase_credentials))
            firebase_admin.initialize_app(cred)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid FIREBASE_CREDENTIALS format: {str(e)}")
    else:
        raise ValueError("FIREBASE_CREDENTIALS environment variable not found.")

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load and preprocess data
data = pd.read_csv('wbjee_final_clean.xls')

# Handle missing values
data['Seat Type'] = data['Seat Type'].fillna('Unknown')
data['Program'] = data['Program'].fillna('Unknown')
data['Category'] = data['Category'].fillna('Unknown')

# Normalize columns
for col in ['Institute', 'Category', 'Round', 'Seat Type', 'Program']:
    data[col] = data[col].str.strip().str.title().str.replace(r'\s+', ' ', regex=True).str.replace('&', 'And')
data['Category'] = data['Category'].str.replace('Obc - A', 'Obc-A').str.replace('Obc - B', 'Obc-B')
data['Program'] = data['Program'].str.replace(r'\s*&\s*', ' And ', regex=True)  # Standardize '&' to 'And'
data['Program'] = data['Program'].str.replace(r'\s+', ' ', regex=True)  # Remove extra spaces
data['Program'] = data['Program'].str.title()  # Ensure consistent title case
data['Year'] = pd.to_numeric(data['Year'], errors='coerce').fillna(0).astype(int)
data = data.drop_duplicates()

# Get unique values for filters
programs = sorted([x for x in data['Program'].unique() if pd.notna(x) and x != 'Unknown'])
categories = sorted([x for x in data['Category'].unique() if pd.notna(x) and x != 'Unknown'])
seat_types = sorted([x for x in data['Seat Type'].unique() if pd.notna(x) and x != 'Unknown'])
rounds = sorted([x for x in data['Round'].unique() if pd.notna(x)])
years = sorted([x for x in data['Year'].unique() if x != 0])

# Verify data
logger.debug(f"Columns: {data.columns.tolist()}")
logger.debug(f"Unique Years: {data['Year'].unique()}")
logger.debug(f"Unique Seat Types: {data['Seat Type'].unique()}")
logger.debug(f"Unique Categories: {data['Category'].unique()}")
logger.debug(f"Unique Programs: {programs}")

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
        decoded_token = auth.verify_id_token(id_token, clock_skew_seconds=60)
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
        * { box-sizing: border-box; }
        body { font-family: 'Poppins', sans-serif; background: linear-gradient(135deg, #e0f7fa, #ffffff); min-height: 100vh; display: flex; flex-direction: column; margin: 0; }
        .header { background-color: #4CAF50; color: white; padding: 1.5rem; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.2); font-size: 1.25rem; }
        .form-container { max-width: 600px; margin: 2rem auto; padding: 2rem; background: white; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); transition: transform 0.3s; }
        .form-container:hover { transform: translateY(-5px); }
        .form-label { font-weight: 600; color: #333; font-size: 1.1rem; }
        .form-control { border-radius: 10px; border: 2px solid #e0e0e0; transition: border-color 0.3s; font-size: 1rem; padding: 0.75rem; min-height: 44px; width: 100%; }
        .form-control:focus { border-color: #4CAF50; box-shadow: 0 0 5px rgba(76,175,80,0.3); }
        .btn-primary { background-color: #4CAF50; border-color: #4CAF50; border-radius: 10px; padding: 0.75rem; font-weight: 600; font-size: 1rem; min-height: 44px; width: 100%; transition: background-color 0.3s; }
        .btn-primary:hover { background-color: #45a049; }
        .spinner { display: none; text-align: center; margin-top: 1rem; }
        .spinner img { width: 30px; }
        footer { margin-top: auto; background-color: #333; color: white; text-align: center; padding: 1.5rem; font-size: 0.9rem; }
        footer a { margin: 0 0.5rem; color: #4CAF50; text-decoration: none; }
        .auth-container { display: none; max-width: 400px; margin: 2rem auto; padding: 2rem; background: white; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .auth-container.active { display: block; }
        .error-message { color: #dc3545; font-size: 0.9rem; margin-top: 0.5rem; display: none; }
        .success-message { color: #28a745; font-size: 0.9rem; margin-top: 0.5rem; display: none; }
        @media (max-width: 576px) { .header { font-size: 1rem; padding: 0.75rem; } .form-container, .auth-container { max-width: 100%; margin: 0.5rem; padding: 1rem; } .form-label { font-size: 0.95rem; } .form-control { font-size: 0.85rem; padding: 0.5rem; min-height: 40px; } .btn-primary { font-size: 0.85rem; padding: 0.5rem; min-height: 40px; } footer { font-size: 0.75rem; padding: 0.75rem; } footer a { display: block; margin: 0.25rem 0; } h2 { font-size: 1.25rem; } }
        @media (max-width: 400px) { .header { font-size: 0.9rem; padding: 0.5rem; } .form-container, .auth-container { margin: 0.25rem; padding: 0.75rem; } .form-label { font-size: 0.9rem; } .form-control { font-size: 0.8rem; padding: 0.4rem; min-height: 36px; } .btn-primary { font-size: 0.8rem; padding: 0.4rem; min-height: 36px; } footer { font-size: 0.7rem; padding: 0.5rem; } h2 { font-size: 1.1rem; } .error-message, .success-message { font-size: 0.8rem; } }
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
                <label class="form-label" for="category">Category</label>
                <select class="form-control" id="category" name="category">
                    <option value="Any" {% if form_data.get('category') == 'Any' %}selected{% endif %}>Any</option>
                    {% for category in categories %}
                        <option value="{{ category }}" {% if form_data.get('category') == category %}selected{% endif %}>{{ category }}</option>
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

        let formDataCache = {};

        window.togglePassword = function (id) {
            const input = document.getElementById(id);
            input.type = input.type === "password" ? "text" : "password";
        };

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
            document.getElementById('reset-password-form').classList.remove('active');
            document.getElementById('predictor-form').style.display = 'block';
            hideErrors();
        };

        function hideErrors() {
            document.getElementById('login-email-error').style.display = 'none';
            document.getElementById('signup-email-error').style.display = 'none';
            document.getElementById('signup-email-exists-error').style.display = 'none';
            document.getElementById('reset-email-error').style.display = 'none';
            document.getElementById('reset-email-success').style.display = 'none';
        }

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
                console.error('Signup failed:', error.code, error.message);
                if (error.code === 'auth/email-already-in-use') {
                    existsError.style.display = 'block';
                } else {
                    existsError.textContent = 'Signup failed: ' + error.message;
                    existsError.style.display = 'block';
                }
            }
        });

        document.getElementById('login-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const emailError = document.getElementById('login-email-error');

            console.log('Attempting login for:', email);

            if (!isValidGmail(email)) {
                emailError.textContent = 'Please enter a valid Gmail address (e.g., abc@gmail.com).';
                emailError.style.display = 'block';
                return;
            }
            emailError.style.display = 'none';

            try {
                const userCredential = await signInWithEmailAndPassword(auth, email, password);
                console.log('Login successful:', userCredential.user.email);
                setTimeout(() => {
                    window.location.href = '/predictor';
                }, 100);
                updateUserInfo(userCredential.user);
            } catch (error) {
                console.error('Login failed:', error.code, error.message);
                if (error.code === 'auth/invalid-credential' || error.code === 'auth/wrong-password' || error.code === 'auth/user-not-found') {
                    emailError.textContent = 'Invalid email or password.';
                    emailError.style.display = 'block';
                } else if (error.code === 'auth/too-many-requests') {
                    emailError.textContent = 'Too many attempts. Please try again later.';
                    emailError.style.display = 'block';
                } else {
                    emailError.textContent = 'Login failed: ' + error.message;
                    emailError.style.display = 'block';
                }
            }
        });

        document.getElementById('reset-password-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('reset-email').value;
            const emailError = document.getElementById('reset-email-error');
            const successMessage = document.getElementById('reset-email-success');

            if (!isValidGmail(email)) {
                emailError.style.display = 'block';
                successMessage.style.display = 'none';
                return;
            }
            emailError.style.display = 'none';
            successMessage.style.display = 'none';

            try {
                await sendPasswordResetEmail(auth, email);
                console.log('Password reset email sent to:', email);
                successMessage.style.display = 'block';
                setTimeout(() => {
                    showLogin();
                    hideErrors();
                }, 3000);
            } catch (error) {
                console.error('Reset password failed:', error.code, error.message);
                emailError.textContent = error.code === 'auth/user-not-found' ? 'No user found with this email.' :
                                        error.code === 'auth/too-many-requests' ? 'Too many requests. Try again later.' :
                                        'Reset failed: ' + error.message;
                emailError.style.display = 'block';
            }
        });

        window.signOut = function () {
            signOut(auth).then(() => {
                console.log('User signed out');
                window.location.href = '/';
            }).catch((error) => {
                console.error('Sign out failed:', error.message);
                alert('Sign out failed: ' + error.message);
            });
        };

        function updateUserInfo(user) {
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('user-email').textContent = user.email;
        }

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
                console.error('Predict error:', error.message);
                alert('Error: ' + error.message);
            } finally {
                document.querySelector('.spinner').style.display = 'none';
                document.querySelector('.btn-primary').disabled = false;
            }
        });

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
        * { box-sizing: border-box; }
        body { font-family: 'Poppins', sans-serif; background: linear-gradient(135deg, #e0f7fa, #ffffff); min-height: 100vh; display: flex; flex-direction: column; margin: 0; }
        .header { background-color: #4CAF50; color: white; padding: 1.5rem; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.2); font-size: 1.25rem; }
        .results-container { max-width: 1200px; margin: 2rem auto; padding: 2rem; background: white; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); transition: transform 0.3s; }
        .results-container:hover { transform: translateY(-5px); }
        .table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        .table { border-radius: 10px; overflow: hidden; font-size: 1rem; min-width: 600px; }
        .table th { background-color: #4CAF50; color: white; position: sticky; top: 0; z-index: 1; padding: 0.75rem; }
        .table td { padding: 0.75rem; vertical-align: middle; white-space: nowrap; }
        .table tbody tr:hover { background-color: #f1f8e9; }
        .btn-primary, .btn-success { background-color: #4CAF50; border-color: #4CAF50; border-radius: 10px; padding: 0.75rem 1.5rem; font-size: 1rem; min-height: 44px; margin: 0.5rem; transition: background-color 0.3s; }
        .btn-primary:hover, .btn-success:hover { background-color: #45a049; }
        .alert { border-radius: 10px; font-size: 1rem; padding: 1rem; word-wrap: break-word; }
        .pagination { margin-top: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; }
        footer { margin-top: auto; background-color: #333; color: white; text-align: center; padding: 1.5rem; font-size: 0.9rem; }
        footer a { margin: 0 0.5rem; color: #4CAF50; text-decoration: none; }
        @media (max-width: 576px) { .header { font-size: 1rem; padding: 0.75rem; } .results-container { max-width: 100%; margin: 0.5rem; padding: 1rem; } .table { font-size: 0.8rem; min-width: 600px; } .table th, .table td { padding: 0.4rem; } .btn-primary, .btn-success { font-size: 0.85rem; padding: 0.5rem 1rem; min-height: 40px; margin: 0.25rem; } .alert { font-size: 0.85rem; padding: 0.75rem; } footer { font-size: 0.75rem; padding: 0.75rem; } footer a { display: block; margin: 0.25rem 0; } h2 { font-size: 1.25rem; } .pagination { flex-direction: column; gap: 0.5rem; } }
        @media (max-width: 400px) { .header { font-size: 0.9rem; padding: 0.5rem; } .results-container { margin: 0.25rem; padding: 0.75rem; } .table { font-size: 0.75rem; min-width: 600px; } .table th, .table td { padding: 0.3rem; } .btn-primary, .btn-success { font-size: 0.8rem; padding: 0.4rem 0.8rem; min-height: 36px; } .alert { font-size: 0.8rem; padding: 0.5rem; } footer { font-size: 0.7rem; padding: 0.5rem; } h2 { font-size: 1.1rem; } }
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
                No colleges found for your rank and filters. Try relaxing filters like Program, Category, or Year.
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

        const formDataCache = {{ form_data|tojson }};

        window.signOut = function () {
            signOut(auth).then(() => {
                console.log('User signed out');
                window.location.href = '/';
            }).catch((error) => {
                console.error('Sign out failed:', error.message);
                alert('Sign out failed: ' + error.message);
            });
        };

        function updateUserInfo(user) {
            document.getElementById('user-info').style.display = 'block';
            document.getElementById('user-email').textContent = user.email;
        }

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
    form_data = {k: urllib.parse.unquote(v) for k, v in request.args.items() if k in ['rank', 'program', 'category', 'seat_type', 'round', 'year']}
    return render_template_string(INDEX_HTML, programs=programs, categories=categories,
                               seat_types=seat_types, rounds=rounds, years=years, form_data=form_data)

@app.route('/predictor')
def predictor():
    form_data = {k: urllib.parse.unquote(v) for k, v in request.args.items() if k in ['rank', 'program', 'category', 'seat_type', 'round', 'year']}
    return render_template_string(INDEX_HTML, programs=programs, categories=categories,
                               seat_types=seat_types, rounds=rounds, years=years, form_data=form_data)

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
        category = form_data.get('category', 'Any')
        seat_type = form_data.get('seat_type', 'Any')
        round = form_data.get('round', 'Any')
        year = form_data.get('year', 'Any')
        
        if not 1 <= rank <= 1000000:
            raise ValueError("Rank must be between 1 and 1,000,000")
            
        logger.debug(f"Input: rank={rank}, program={program}, category={category}, seat_type={seat_type}, round={round}, year={year}, page={page}")
        
        filtered_data = data.copy()
        low_rank_message = None
        min_rank_message = None
        temp_data = filtered_data.copy()

        # Determine the starting closing rank based on rank range
        if rank < 20000:
            start_closing_rank = max(1, rank - 5000)
        elif 20000 <= rank <= 30000:
            start_closing_rank = 13000
        elif 30000 <= rank <= 50000:
            start_closing_rank = 19000
        else:  # rank > 50000
            start_closing_rank = 26000

        # Apply filters
        if program != 'Any':
            temp_data = temp_data[temp_data['Program'] == program]
        if category != 'Any':
            temp_data = temp_data[temp_data['Category'] == category]
        if seat_type != 'Any':
            temp_data = temp_data[temp_data['Seat Type'] == seat_type]
        if round != 'Any':
            temp_data = temp_data[temp_data['Round'] == round]
        if year != 'Any':
            temp_data = temp_data[temp_data['Year'] == int(year)]

        # Filter data based on closing rank range
        if temp_data.empty or 'Closing Rank' not in temp_data.columns:
            min_rank_message = "No colleges found for these filters. Try relaxing filters like Program, Category, or Year."
            filtered_data = pd.DataFrame(columns=data.columns)
        else:
            max_closing_rank = temp_data['Closing Rank'].max()
            filtered_data = temp_data[temp_data['Closing Rank'] >= start_closing_rank]
            if filtered_data.empty:
                min_rank_message = f"No colleges found with closing ranks >= {start_closing_rank} for rank {rank}. Showing all available data."
                filtered_data = temp_data.copy()

        # Sort by Closing Rank in ascending order
        if not filtered_data.empty:
            filtered_data = filtered_data.sort_values(by='Closing Rank', ascending=True)

        # Save results
        if not filtered_data.empty:
            filtered_data.to_csv('results.csv', index=False)

        total_results = len(filtered_data)
        start = (page - 1) * per_page
        end = min(start + per_page, total_results)
        paginated_results = filtered_data.iloc[start:end][['Institute', 'Program', 'Round', 'Category', 'Seat Type', 'Opening Rank', 'Closing Rank', 'Year']].to_dict('records')
        has_next = end < total_results
        form_data['page'] = str(page)
        
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