import os
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

# Configuration
SECRET_KEY = os.getenv('SECRET_KEY', 'supersecretkey')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
STUDENTS_FILE = os.path.join(DATA_DIR, 'students.json')

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(default, f, indent=2)
        return default
    with open(path, 'r') as f:
        return json.load(f)

def save_json(path, data):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

# Ensure at least one admin user exists (email: admin@admin.com, password: admin123)
users = load_json(USERS_FILE, [])
if not any(u.get('role') == 'admin' for u in users):
    admin_user = {
        'id': int(datetime.utcnow().timestamp()),
        'email': 'admin@admin.com',
        'password': generate_password_hash('admin123'),
        'role': 'admin'
    }
    users.append(admin_user)
    save_json(USERS_FILE, users)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth or not auth.startswith('Bearer '):
            return jsonify({'msg': 'Token missing'}), 401
        token = auth.split(' ')[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = payload
        except jwt.ExpiredSignatureError:
            return jsonify({'msg': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'msg': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    if not email or not password:
        return jsonify({'msg': 'Missing fields'}), 400
    users = load_json(USERS_FILE, [])
    if any(u['email'] == email for u in users):
        return jsonify({'msg': 'User exists'}), 409
    new_user = {
        'id': int(datetime.utcnow().timestamp()),
        'email': email,
        'password': generate_password_hash(password),
        'role': role
    }
    users.append(new_user)
    save_json(USERS_FILE, users)
    token = jwt.encode({
        'id': new_user['id'],
        'email': new_user['email'],
        'role': new_user['role'],
        'exp': datetime.utcnow() + timedelta(hours=2)
    }, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email') or data.get('username')
    password = data.get('password')
    users = load_json(USERS_FILE, [])
    user = next((u for u in users if u['email'] == email), None)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'msg': 'Invalid credentials'}), 401
    token = jwt.encode({
        'id': user['id'],
        'email': user['email'],
        'role': user['role'],
        'exp': datetime.utcnow() + timedelta(hours=2)
    }, SECRET_KEY, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/api/students', methods=['GET'])
@token_required
def get_students():
    if request.user.get('role') != 'admin':
        return jsonify({'msg': 'Forbidden'}), 403
    students = load_json(STUDENTS_FILE, [])
    return jsonify(students)

@app.route('/api/students', methods=['POST'])
@token_required
def save_student():
    if request.user.get('role') != 'admin':
        return jsonify({'msg': 'Forbidden'}), 403
    payload = request.get_json()
    student_id = payload.get('studentId')
    data = payload.get('data')
    if not student_id or not data:
        return jsonify({'msg': 'Invalid payload'}), 400
    students = load_json(STUDENTS_FILE, [])
    existing = next((s for s in students if s.get('studentId') == student_id), None)
    if existing:
        existing['data'] = data
    else:
        students.append({'studentId': student_id, 'data': data})
    save_json(STUDENTS_FILE, students)
    return jsonify({'msg': 'Saved'})

@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({'ok': True})

if __name__ == '__main__':
    # Run on the same port the front‑end expects (3000)
    app.run(host='0.0.0.0', port=3000, debug=True)
