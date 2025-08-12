from flask import Flask, jsonify, request , render_template
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import joblib
import os
import jwt
import json
from flask_cors import CORS
import numpy as np
# from flask_cors import CORS
import smtplib
from dotenv import load_dotenv
from email.message import EmailMessage
import pandas as pd
from datetime import datetime, timedelta
from functools import wraps



app = Flask(__name__)
bcrypt = Bcrypt(app)
# CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})  
CORS(app)
load_dotenv() 
api_key = os.getenv("MongoDB_API_KEY")
secret_key = os.urandom(24)
sender_email = os.getenv("SENDER_EMAIL")
sender_key = os.getenv("SENDER_KEY")
client = MongoClient(
    api_key)
db = client['Mindwell']
collection = db['Data']
otp_collection = db['OTP']

otp_collection = db['otp_verifications']

# One-time TTL index setup (skip on subsequent runs)
try:
    otp_collection.create_index('otpExpiryAt', expireAfterSeconds=0)
except Exception as e:
    print("Index creation error (probably already exists):", e)
# CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/",methods=['GET'])
def testing():
    try:
        #return index.html file
        return render_template('index.html')
        
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    
@app.route("/signup", methods=['POST'])
def signup():
    try:
        data = request.json
        name = data['name']
        username = data['username']
        password = data['password']
        email = data['email']

        # print("Received signup request from:", email)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        existing = collection.find_one({'email': {'$regex': f'^{email}$', '$options': 'i'}})
        existingusername = collection.find_one({'username': {'$regex': f'^{username}$', '$options': 'i'}})

        if existing:
            print("Email already registered")
            return jsonify({'message': "Already registered"}), 409
        elif existingusername:
            print("Username already taken")
            return jsonify({'message': "Username not available"}), 409
        else:
            email_exists = otp_collection.find_one({'email': email})
            if email_exists:
                print("Email already exists in OTP collection")
                otp_collection.delete_one({'email': email})
            otp = otp_generator()
            expiry = datetime.utcnow() + timedelta(minutes=2)
            # print(f"Generated OTP for {email}: {otp}")
            
            user = {
                'name': name,
                'username': username,
                'password': hashed_password,
                'email': email,
                'otp': otp,
                'request_type': 'signup',
                'otpExpiryAt': expiry
            }
            send_otp(email, otp)
            otp_collection.insert_one(user)

            return jsonify({
                'status': 'success',
                'message': 'Please verify OTP.',
                'email': email
            }), 201

    except Exception as e:
        print("Signup error:", e)
        return jsonify({'error': str(e)}), 500

def otp_generator():
    otp = np.random.randint(100000, 999999)
    return otp

def complete(email):
    try:
        db = otp_collection.find_one({'email':email})
        new_entry ={
                'email':email,
                'name': db['name'],
                'username': db['username'],
                'password': db['password']
            }
        collection.insert_one(new_entry)
        otp_collection.delete_one({'email': email})
        return jsonify({'message': 'Account created successfully', 'email': email})
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    
@app.route("/signin", methods=['POST'])
def signin():
    try:
        data = request.json
        print(data)
        email = data['email']
        password = data['password']
        user = collection.find_one({'email': email})
        if user and bcrypt.check_password_hash(user['password'], password):
            token = jwt.encode({'email': email}, secret_key, algorithm='HS256')
            return jsonify({'email': email,'token': token})
        else:
            return jsonify({'message': 'User not found or incorrect password'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/forget',methods=['POST'])
def forget():
    try:
        data = request.json
        email = data['email']
        user = collection.find_one({'email': email})
        otp = otp_generator()
            #sending OTP to the user via Email
        print(f"OTP for {email} is {otp}")
        try:
            #otp saving in the database or cache can be implemented here
            expiry = datetime.utcnow() + timedelta(minutes=1)
            otp_collection.insert_one({
            'email': email,
            'otp': otp,
            'otpExpiryAt': expiry,
            'request_type': 'forget'
            })
            print(f"OTP saved to database for {email}")
            send_otp(email, otp)
            return jsonify({'message': 'OTP sent to your email', 'email': email})
        except Exception as e:
            print(f"Error saving OTP to database: {str(e)}")
            return jsonify({'error': 'Failed to save OTP'}), 500
            # Store OTP in the database or cache with an expiration time
        # return jsonify({'message': 'OTP sent to your email', 'email': email})
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    
def send_otp(email, otp):
    try:
        msg = EmailMessage()
        msg['Subject'] = 'Your OTP for Password Reset'
        msg['From'] = sender_email
        msg['To'] = email
        msg.set_content(f'Your OTP for password reset is {otp}. It is valid for 5 minutes.')
        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
                smtp.login(sender_email, sender_key)
                smtp.send_message(msg)
        except smtplib.SMTPException as e:
            print(f"SMTP error: {str(e)}")
            # raise Exception("Failed to send email. Please check your SMTP settings.")
            return jsonify({'error': 'Failed to send OTP via email'}), 500
    except Exception as e:
        print(f"Error sending OTP: {str(e)}")
        return jsonify({'error': 'Failed to send OTP'}), 500
    
@app.route('/verify', methods=['POST'])
def verify():
    try:
        data =request.json
        email = data['email']
        otp = data['otp']
        print(email)
        otp_int = int(otp)
        
        db = otp_collection.find_one({'email': email})
        if not db:
            return jsonify({'message': 'Email not found'}), 404
        if 'otp' not in db:
            return jsonify({'message': 'OTP Expired'}), 400
        if db['otp'] == otp_int:
            request_type = db['request_type']
            token = jwt.encode({'email': email}, secret_key, algorithm='HS256')
            # print(f"OTP verified for {email}, request type: {request_type}")
            
            if request_type == 'signup':
                complete(email)
            otp_collection.delete_one({'email': email})
            return jsonify({'message': 'OTP verified successfully' ,'type':request_type, 'token': token})
        else:
            return jsonify({'message': 'Invalid OTP'}), 400 
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    
@app.route('/update-password', methods=['POST'])
def update_password():
    try:
        data = request.json
        email = data['email']
        new_password = data['new_password']
        token = data['token']
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        try:
            user = collection.find_one({'email': email})
            if not user:
                return jsonify({'error': 'User not found'}), 404
            collection.update_one({'email': email}, {'$set': {'password': bcrypt.generate_password_hash(new_password).decode('utf-8')}})
            return jsonify({'message': 'Password updated successfully'}), 200
        except Exception as e:
            print(f"Error updating password: {str(e)}")
            return jsonify({'error': 'Failed to update password'}), 500
        # return jsonify({'message': 'Password updated successfully'}), 200
    except Exception as e:
        print(e)
        
        return jsonify({'error': str(e)}), 500

@app.route('/update', methods=['POST'])
def update():
    try:
        data = request.json
        email = data['email']
        password = data['password']
        newpass = data['newpassword']

        user = collection.find_one({'email': email})

        if user and user['password'] == password:
            collection.update_one(
                {'email': email}, {'$set': {'password': newpass}})
            return jsonify({"message": "Password updated successfully"})
        else:
            return jsonify({"message": "User not found or incorrect password"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/delete', methods=['DELETE'])
def delete():
    try:
        data = request.json
        email = data['email']
        password = data['password']

        user = collection.find_one({'email': email})

        if user and user['password'] == password:
            collection.delete_one({'email': email})
            return jsonify({"message": "User deleted successfully"})
        else:
            return jsonify({"message": "User not found or incorrect password"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
model = joblib.load('trained_model.pkl')
X_columns = [
    'Age', 'Gender', 'Country', 'self_employed', 'family_history',
    'work_interfere', 'no_employees', 'remote_work', 'tech_company',
    'benefits', 'care_options', 'wellness_program', 'seek_help',
    'anonymity', 'leave', 'mental_health_consequence',
    'phys_health_consequence', 'coworkers', 'supervisor',
    'mental_health_interview', 'phys_health_interview',
    'mental_vs_physical', 'obs_consequence'
]
@app.route("/dashboard", methods=['GET'])
def dashboard():
    try:
        data = request.json
        email = data.get('email')
        # Return dashboard data for the authenticated user
        db = collection.find_one({'email': email})
        if not db:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'status': 'success',
            'user': {
                'name': db['name'],
                'email': db['email'],
                'username': db['username']
            },
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict', methods=['POST'])
def predict():
    print("Incoming request:", request.json)

    data = request.get_json()
    # with open("input_log.json", "a") as f:
    #     f.write(json.dumps(data) + "\n")
    #     f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
    try:
        answers = data["answers"]
        questions = data.get("questions", [])
        print("150")
        if len(answers) != len(X_columns):
            print("151")
            return jsonify({"error": "Mismatch between answer length and expected input format."}), 400
    except (KeyError, ValueError, TypeError) as e:
        print("153")
        return jsonify({"error": f"Invalid input format: {str(e)}"}), 400

    # Create DataFrame with column names
    try:
        input_df = pd.DataFrame([answers], columns=X_columns)
    except Exception as e:
        return jsonify({"error": f"Failed to convert input to DataFrame: {str(e)}"}), 500
    try:
        prediction = model.predict(input_df)
        # prediction_prob = model.predict_proba(input_df)[0] if hasattr(model, "predict_proba") else None
    except Exception as e:
        # print("164")
        print("Error during prediction:", str(e))
        return jsonify({"error": f"Model prediction failed: {str(e)}"}), 500

    # Logging prediction
    with open("prediction_log.json", "a") as f:
        f.write(json.dumps({
            "prediction": int(prediction[0]),
            "answers": answers
        }) + "\n")
    if prediction[0] == 0:
        remarks = "You are doing great! Keep up the good work!"
    elif prediction[0] == 1:
        remarks = "You are doing okay, but there is room for improvement."
    else:
        remarks = "You might be facing some challenges, consider seeking help."
    return jsonify({
        "mentalState": int(prediction[0]),
        "remarks": remarks,
    }), 200

@app.route('/activities', methods=['GET'])
def get_activities():
    activities = [
    {
        "id": "act_001",
        "title": "Morning Meditation",
        "duration": 10,
        "category": "Mindfulness"
    },
    {
        "id": "act_002",
        "title": "Gratitude Journaling",
        "duration": 5,
        "category": "Reflection"
    },
    {
        "id": "act_003",
        "title": "Breathing Exercise",
        "duration": 3,
        "category": "Relaxation"
    },
    {
        "id": "act_004",
        "title": "Stretching Routine",
        "duration": 7,
        "category": "Physical Wellness"
    },
    {
        "id": "act_005",
        "title": "Read a Motivational Quote",
        "duration": 2,
        "category": "Inspiration"
    },
    {
        "id": "act_006",
        "title": "Hydrate Yourself",
        "duration": 1,
        "category": "Health"
    },
    {
        "id": "act_007",
        "title": "Write a To-Do List",
        "duration": 5,
        "category": "Productivity"
    },
    {
        "id": "act_008",
        "title": "Listen to Calming Music",
        "duration": 8,
        "category": "Relaxation"
    },
    {
        "id": "act_009",
        "title": "Take a Nature Walk",
        "duration": 15,
        "category": "Physical Wellness"
    },
    {
        "id": "act_010",
        "title": "Practice Deep Focus",
        "duration": 20,
        "category": "Mindfulness"
    }
]

    return jsonify({"status": "success", "activities": activities})

@app.route('/meditations', methods=['GET'])
def get_meditations():
    meditations = [
        {
            "id": "med_001",
            "title": "Deep Breathing",
            "duration": 5,
            "level": "Beginner"
        },
        {
            "id": "med_002",
            "title": "Body Scan",
            "duration": 15,
            "level": "Intermediate"
        },
        {
            "id": "med_003",
            "title": "Loving-Kindness",
            "duration": 20,
            "level": "Advanced"
        }
    ]
    return jsonify({"status": "success", "meditations": meditations})

@app.route('/analytics', methods=['GET'])
def get_analytics():
    analytics = {
        "mood_trend": [3, 4, 5, 4, 5, 6, 7],
        "activity_completion": 75,
        "stress_level": "medium",
        "sleep_quality": "good",
        "weekly_summary": {
            "meditation_minutes": 120,
            "activities_completed": 8,
            "mood_avg": 5.2
        }
    }
    return jsonify({"status": "success", "analytics": analytics})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)