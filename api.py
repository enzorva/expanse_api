import sqlite3
import datetime
import uuid
import jwt
import os
import bcrypt
from dotenv import load_dotenv      
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.user_id = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(*args, **kwargs)
    return decorated

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('database.db')
    g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    db.execute('''
        CREATE TABLE IF NOT EXISTS expanses (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    ''')

# ------- User Authentication Routes ---------

@app.route('/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    db = get_db()
    user_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    db.execute('''
        INSERT INTO users (id, username, email, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?)''', 
        (user_id, data['username'], data['email'], hashed_password, now)
    )
    db.commit()
    return jsonify({'id': user_id, 'username': data['username'], 'email': data['email']}), 201

@app.route('/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    db = get_db()
    user = db.execute('''
        SELECT * FROM users WHERE username = ?
    ''', (data['username'],)).fetchone()

    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user['password_hash']):
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'token': token,
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials!'}), 401
    
@app.route('/auth/logout', methods=['POST'])
def logout_user():
    return jsonify({'message': 'Logged out successfully!'}), 200

# --------- Expanses Routes ---------

@app.route('/expanses', methods=['GET'])
@token_required
def get_expanses():
    db = get_db()
    user_id = g.user_id['user_id']
    filter_type = request.args.get('filter')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    today = datetime.date.today()

    if filter_type == 'week':
        start_date = (today - datetime.timedelta(days=7)).isoformat()
        end_date = today.isoformat()
    elif filter_type == 'month':
        start_date = (today - datetime.timedelta(days=30)).isoformat()
        end_date = today.isoformat()
    elif filter_type == '3months':
        start_date = (today - datetime.timedelta(days=90)).isoformat()
        end_date = today.isoformat()
    # For 'custom', start_date and end_date are provided by the user

    query = 'SELECT * FROM expanses WHERE user_id = ?'
    params = [user_id]
    if start_date:
        query += ' AND date(created_at) >= date(?)'
        params.append(start_date)
    if end_date:
        query += ' AND date(created_at) <= date(?)'
        params.append(end_date)

    expanses = db.execute(query, params).fetchall()
    result = [
        {
            'id': expanse['id'],
            'amount': expanse['amount'],
            'description': expanse['description'],
            'category': expanse['category'],
            'created_at': expanse['created_at']
        }
        for expanse in expanses
    ]
    return jsonify(result), 200

@app.route('/expanses/<expanse_id>', methods=['GET'])
@token_required
def get_expanse(expanse_id):
    db = get_db()
    user_id = g.user_id['user_id']
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = 'SELECT * FROM expanses WHERE user_id = ?'
    params = [user_id]

    if start_date:
        query += ' AND date(created_at) >= date(?)'
        params.append(start_date)
    if end_date:
        query += ' AND date(created_at) <= date(?)'
        params.append(end_date)

    expanses = db.execute(query, params).fetchall()
    result = [
        {
            'id': expanse['id'],
            'amount': expanse['amount'],
            'description': expanse['description'],
            'category': expanse['category'],
            'created_at': expanse['created_at']
        }
        for expanse in expanses
    ]
    return jsonify(result), 200

@app.route('/expanses', methods=['POST'])
@token_required
def add_expanse():
    data = request.get_json()
    db = get_db()
    user_id = g.user_id['user_id']
    db.execute('''
        INSERT INTO expanses (id, user_id, amount, description)
        VALUES (?, ?, ?, ?)
    ''', (str(uuid.uuid4()), user_id, data['amount'], data['description']))
    db.commit()
    return jsonify({'message': 'Expanse added successfully!'}), 201

@app.route('/expanses/<expanse_id>', methods=['PUT'])
@token_required
def update_expanse(expanse_id):
    data = request.get_json()
    db = get_db()
    user_id = g.user_id['user_id']
    db.execute('''
        UPDATE expanses SET amount = ?, description = ?, category = ?
        WHERE id = ? AND user_id = ?
    ''', (data['amount'], data['description'], data['category'], expanse_id, user_id))
    db.commit()
    return jsonify({'message': 'Expanse updated successfully!'}), 200

@app.route('/expanses/<expanse_id>', methods=['DELETE'])
@token_required
def delete_expanse(expanse_id):
    db = get_db()
    user_id = g.user_id['user_id']
    db.execute('''
        DELETE FROM expanses WHERE id = ? AND user_id = ?
    ''', (expanse_id, user_id))
    db.commit()
    return jsonify({'message': 'Expanse deleted successfully!'}), 200

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)