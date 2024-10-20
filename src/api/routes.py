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

    # Consulta la base de datos para validar al usuario
    user = User.query.filter_by(email=email).first()

    # Verifica si el usuario existe y si la contraseña es correcta
    if not user or not check_password_hash(user.password, password):
        # el usuario no se encontró en la base de datos
        return jsonify({"msg": "Credenciales incorrectas."}), 401
    
     # Crear tokens de acceso y refresco
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    response = jsonify({'msg': 'Login exitoso'})
    set_access_cookies(response, access_token)  # Almacena el access_token en una cookie HttpOnly
    set_refresh_cookies(response, refresh_token)  # Almacena el refresh_token en una cookie HttpOnly
    return response, 200

@api.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True) 
def refresh():
    current_user = get_jwt_identity()   # Obtiene el usuario actual desde el token de refresh
    new_access_token = create_access_token(identity=current_user)   
    
    response = jsonify({'msg': 'Access token refrescado'})
    set_access_cookies(response, new_access_token)  # Guardar el nuevo access token en la cookie
    return response, 200


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
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    # Validar si el usuario o email ya existen
    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "Ese usuario ya existe"}), 400
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "Ese email ya está registrado"}), 400
    if not email or not password:
            return jsonify({"error": "Email y contraseña son requeridos"}), 400
    
    # Hashear la contraseña
    hashed_password = generate_password_hash(password)
    
    # Crear el nuevo usuario
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        username=username,
        email=email,
        password=hashed_password,
        is_active=False
    )
    
    # Guardar el usuario en la base de datos
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuario registrado exitosamente!"}), 201

# Obtener todos los usuarios
@api.route('/users', methods=['GET'])
@jwt_required
def get_users():
    # Obtener la identidad del usuario desde el token
    current_user_id = get_jwt_identity()

    # Obtener el array de usuarios regitrados 
    users = User.query.all()
    users_list = [{
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "email": user.email
    } for user in users]
    
    return jsonify(users_list), 200


# Proteger la ruta privada
@api.route('/private', methods=['GET'])
@jwt_required()
def private_route():
    # Obtener la identidad del usuario desde el token
    current_user_id = get_jwt_identity()

    # Realizar lógica de la ruta, por ejemplo, devolver datos del usuario
    return jsonify({"message": f"Acceso permitido para el usuario {current_user_id}"}), 200