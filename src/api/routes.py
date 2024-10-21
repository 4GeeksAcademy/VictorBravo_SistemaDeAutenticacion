"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS 
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, set_access_cookies, unset_access_cookies, set_refresh_cookies, unset_jwt_cookies
from werkzeug.security import check_password_hash, generate_password_hash 

api = Blueprint('api', __name__)

@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

# Login con Token JWT
@api.route("/token", methods=["POST"])
def login():
    email = request.json.get("email")
    password = request.json.get("password")
    remember = request.json.get("remember", False)  # Obtenemos el estado de "Recuérdame"

    # Busca al usuario por email
    user = User.query.filter_by(email=email).first()

    # Verifica si el usuario existe
    if not user:
        return jsonify({"msg": "El email no está registrado."}), 404

    # Verifica si la contraseña es correcta
    if not check_password_hash(user.password, password):
        return jsonify({"msg": "La contraseña es incorrecta."}), 401
    
     # Crear un token de acceso
    access_token = create_access_token(identity=user.id)

    # Crea la respuesta
    response = jsonify({'msg': 'Login exitoso'})

    # Establece la cookie para el token
    if remember:
        set_access_cookies(response, access_token, max_age=30 * 24 * 60 * 60)  # Cookie válida por 30 días
    else:
        set_access_cookies(response, access_token)  # Cookie válida solo durante la sesión

    # Encabezados de control de caché
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response, 200

@api.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True) 
def refresh():
    current_user = get_jwt_identity()   # Obtiene el usuario actual desde el token de refresh
    new_access_token = create_access_token(identity=current_user)   
    
    response = jsonify({'msg': 'Access token refrescado'})
    set_access_cookies(response, new_access_token)  # Guardar el nuevo access token en la cookie
    return response, 200

# Logout borrando token
@api.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"msg": "Logout exitoso"})
    unset_jwt_cookies(response)  # Elimina las cookies con el token
    return response, 200

# Crear usuarios
@api.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Datos del usuario
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    
  # Validar si todos los campos requeridos están presentes
    if not email or not password or not first_name or not last_name:
        return jsonify({"error": "Todos los campos son obligatorios."}), 400

    # Validar si el formato del email es correcto (simple regex para validación)
    import re
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, email):
        return jsonify({"error": "El formato del email es inválido."}), 422

    # Validar si el email ya está registrado
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "Ese email ya está registrado."}), 409

    # Validar si la contraseña cumple con los requisitos
    # (mínimo 8 caracteres, al menos una mayúscula, un número y un carácter especial)
    if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[0-9]', password) or not re.search(r'[\W_]', password):
        return jsonify({"error": "La contraseña debe tener al menos 8 caracteres, una mayúscula, un número y un carácter especial."}), 422
    
    # Hashear la contraseña
    hashed_password = generate_password_hash(password)
    
    # Crear el nuevo usuario
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
    )
    
    # Guardar el usuario en la base de datos
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado correctamente!"}), 201

# Obtener todos los usuarios
@api.route('/users', methods=['GET'])
def get_users():

    # Obtener el array de usuarios regitrados 
    users = User.query.all()
    users_list = [{
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email
    } for user in users]
    
    return jsonify(users_list), 200
