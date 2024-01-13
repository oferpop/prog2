from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_bcrypt import Bcrypt
app = Flask(__name__)
bcrypt = Bcrypt(app)
CORS(app)  # Enable CORS for all routes
api = Api(app)

# JWT Setup
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Replace with your actual secret key
jwt = JWTManager(app)

# SQLite Setup
db_file_path = 'sqlite:///your_database_file.db'  # Replace with the path to your SQLite database file
app.config['SQLALCHEMY_DATABASE_URI'] = db_file_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking
db = SQLAlchemy(app)

# Define your SQLAlchemy models here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create the database tables based on the models
with app.app_context():
    db.create_all()

UPLOAD_FOLDER = 'backend/static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class Hello(Resource):
    def get(self):
        return send_from_directory('../frontend', 'index.html')

class UploadImage(Resource):
    def post(self):
        if 'file' not in request.files:
            return {"error": "No file part"}, 400

        file = request.files['file']
        if file.filename == '':
            return {"error": "No selected file"}, 400

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return {"message": "File uploaded successfully", "filename": filename}, 200

class ListImages(Resource):
    def get(self):
        images = os.listdir(app.config['UPLOAD_FOLDER'])
        image_urls = [f"http://127.0.0.1:5000/static/uploads/{image}" for image in images]
        return {"images": image_urls}

api.add_resource(Hello, '/')
api.add_resource(UploadImage, '/upload')
api.add_resource(ListImages, '/images')

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# @app.route('/login', methods=['POST'])
# def login():
#     username = request.json.get('username', None)
#     password = request.json.get('password', None)
    
#     # Query the database to find the user by username
#     user = User.query.filter_by(username=username).first()
    
#     if user:
#         # User exists, verify the password
#         if check_password_hash(user.password, password):
#             # Password is correct, generate an access token
#             access_token = create_access_token(identity=username)
#             return jsonify(access_token=access_token), 200
#         else:
#             # Invalid password
#             return jsonify({"msg": "Invalid password"}), 401
#     else:
#         # User does not exist
#         return jsonify({"msg": "User not found"}), 401

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
 
    # Validate user here (e.g., check if username already exists)
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"msg": "Username already exists"}), 400

    # Hash the password securely before storing it
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
 
    # Create a new user with the hashed password
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
 
    return jsonify({"msg": "Registration successful"}), 200

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
 
    # Query the database to find the user by username
    user = User.query.filter_by(username=username).first()
 
    if user:
        # User exists, verify the password using bcrypt
        if bcrypt.check_password_hash(user.password, password):
            # Password is correct, generate an access token
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token), 200
        else:
            # Invalid password
            return jsonify({"msg": "Invalid password"}), 401
    else:
        # User does not exist
        return jsonify({"msg": "User not found"}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'msg': f'Welcome {current_user}, you are viewing a protected endpoint!'})

if __name__ == '__main__':
    app.run(debug=True)
