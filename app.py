from flask import Flask, request, jsonify, send_from_directory
from flask_bcrypt import Bcrypt
import jwt
import mysql.connector
from functools import wraps
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bagi2134'  # Ganti dengan kunci rahasia Anda sendiri
bcrypt = Bcrypt(app)

# Koneksi ke database MySQL
db = mysql.connector.connect(
    host='localhost',
    user='root',
    password='',
    database='app_bagi'
)

# Decorator untuk memeriksa keaslian token
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            bearer_token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else None

            if bearer_token:
                token = bearer_token

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['email']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

# Fungsi untuk memeriksa apakah tipe file diizinkan
def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
# Path folder penyimpanan file avatar
UPLOAD_FOLDER = 'avatars'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# Route untuk registrasi
@app.route('/register', methods=['POST'])
def register():
    nama = request.json.get('nama')
    email = request.json.get('email')
    phone = request.json.get('phone')
    username = request.json.get('username')
    password = request.json.get('password')

    if nama and email and phone and username and password:
        if len(password) < 8:
            return jsonify({'error': True, 'message': 'Password must be at least 8 characters long!'}), 400

        cursor = db.cursor()
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            cursor.execute("INSERT INTO users (nama, email, phone, username, password) VALUES (%s, %s, %s, %s, %s)",
                           (nama, email, phone, username, hashed_password))
            db.commit()
        except mysql.connector.IntegrityError as err:
            error_message = str(err)
            if 'username' in error_message or 'email' in error_message:
                return jsonify({'error': True, 'message': 'Email or Username already exist!'}), 400
            
        return jsonify({'error': False, 'message': 'User registered successfully!'})

    return jsonify({'error': True, 'message': 'Invalid data!'}), 400


# Route untuk login
@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    if email and password:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[5], password):
            token = jwt.encode({'email': user[4]}, app.config['SECRET_KEY'], algorithm='HS256')
            login_result = {
                'userId': user[0],
                'name': user[1],
                'token': token
            }
            return jsonify({'error': False, 'message': 'success', 'loginResult': login_result})

    return jsonify({'error': True, 'message': 'Invalid email or password!'})

# route untuk profile
@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username=%s", (current_user,))
    user = cursor.fetchone()

    if user:
        user_data = {
            'id': user[0],
            'nama': user[1],
            'email': user[2],
            'phone': user[3],
            'username': user[4]
        }
        return jsonify({'error': False, 'profile': user_data}), 200
    else:
        return jsonify({'error': True, 'message': 'User not found'}), 404

# route untuk edit profile
@app.route('/profile', methods=['PUT'])
@token_required
def edit_profile(current_user):
    cursor = db.cursor()

    # Mengambil data profil pengguna yang akan diubah
    cursor.execute("SELECT * FROM users WHERE username=%s", (current_user,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Mendapatkan data baru dari body permintaan
    data = request.json
    new_username = data.get('username', user[4])
    new_nama = data.get('nama', user[1])
    new_email = data.get('email', user[2])
    new_phone = data.get('phone', user[3])
    new_password = data.get('password', user[5])

    # Memperbarui data profil pengguna
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    cursor.execute("UPDATE users SET username=%s, nama=%s, email=%s, phone=%s, password=%s WHERE username=%s",
                   (new_username, new_nama, new_email, new_phone, hashed_password, current_user))
    db.commit()

    # Mengambil data profil yang telah diperbarui
    cursor.execute("SELECT * FROM users WHERE username=%s", (new_username,))
    updated_user = cursor.fetchone()

    user_data = {
        'id': updated_user[0],
        'nama': updated_user[1],
        'email': updated_user[2],
        'phone': updated_user[3],
        'username': updated_user[4]
    }

    return jsonify({'error': False, 'message': 'Profile updated successfully!', 'profile': user_data})

# Route untuk mengunggah file avatar
@app.route('/upload_avatar', methods=['POST'])
@token_required
def upload_avatar(current_user, *args, **kwargs):
    # Periksa apakah file avatar ada dalam request
    if 'avatar' not in request.files:
        return jsonify({'message': 'No avatar file uploaded!'}), 400

    avatar = request.files['avatar']

    # Periksa apakah file avatar memiliki nama file dan memiliki ekstensi yang diperbolehkan
    if avatar.filename == '':
        return jsonify({'message': 'Invalid avatar file!'}), 400

    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}

    if not allowed_file(avatar.filename, allowed_extensions):
        return jsonify({'message': 'Invalid file extension!'}), 400

    # Simpan file avatar ke folder yang ditentukan
    filename = secure_filename(avatar.filename)
    avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    return jsonify({'message': 'Avatar uploaded successfully!', 'filename': filename}), 200

# Route untuk mengambil file avatar berdasarkan nama file
@app.route('/avatar/<filename>', methods=['GET'])
@token_required
def get_avatar(current_user, filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# # Route to get all users
# @app.route('/users', methods=['GET'])
# @token_required
# def get_all_users(current_user):
#     cursor = db.cursor()
#     cursor.execute("SELECT * FROM users")
#     users = cursor.fetchall()

#     user_list = []
#     for user in users:
#         user_data = {
#             'id': user[0],
#             'nama': user[1],
#             'email': user[2],
#             'phone': user[3],
#             'username': user[4]
#         }
#         user_list.append(user_data)

#     return jsonify({'users': user_list})

# # Route untuk logout
# @app.route('/logout')
# @token_required
# def logout():
#     # Jika token valid, pengguna dianggap telah logout
#     return jsonify({'message': 'User logged out successfully!'})


if __name__ == '__main__':
    app.run()