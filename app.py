
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from model import mongo, init_db
from config import config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId



app = Flask(__name__)
app.config.from_object(config)


bcrypt = Bcrypt(app)
jwt = JWTManager(app)

#Inicializamos el acceso a MongoDB
init_db(app)


#Utilizamos el decorador @app.route('/') para definir la ruta de la URL e inmediatamente después
#la función que se ejecutará en esa ruta
@app.route('/register', methods=['POST'])
def register():
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Ese usuario ya existe"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # mongo.db.users.insert_one devuelve un objeto con dos propiedades "acknowledged" 
    # si se guardo correctamente y el id del documento insertado
    result = mongo.db.users.insert_one({"username":username,"email":email,"password": hashed_password})
    if result.acknowledged:
        return jsonify({"msg": "Usuario Creado Correctamente"}), 201
    else:
        return jsonify({"msg": "Hubo un error, no se pudieron guardar los datos"}),400
    
    #Definir ruta login
@app.route('/login', methods=['POST'])
def login():
    data= request.get_json()
    email=data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({"email":email})

    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token),200
    else:
        return jsonify({"msg":"Credenciales incorrectas"}), 401
#Endpoint protegido   
@app.route('/datos', methods=['POST'])
@jwt_required()
def datos():
    data= request.get_json()
    username = data.get('username')

    usuario=mongo.db.users.find_one({"username":username}, {"password":0})
    if usuario:
        usuario["_id"]=str(usuario["_id"])
        return jsonify({"msg":"Usuario encontrado", "Usuario":usuario}), 200
    else:
        return jsonify({"msg": "Usuario no encontrado"}), 404


#Endpoint para agregar coche
@app.route('/add_car', methods=['POST'])
@jwt_required()
def add_car():
    data = request.get_json()
    user_id = get_jwt_identity()  # Obtener el ID del usuario del token JWT
    modelo = data.get('modelo')
    anio = data.get('año')
    color = data.get('color')
    placas = data.get('placas')

    # Verificar que el usuario exista
    usuario = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if not usuario:
        return jsonify({"msg": "Usuario no encontrado"}), 404

    # Insertar coche en la colección de coches
    nuevo_coche = {
        "user_id": ObjectId(user_id),
        "modelo": modelo,
        "año": anio,
        "color": color,
        "placas": placas
    }
    
    result = mongo.db.cars.insert_one(nuevo_coche)
    if result.acknowledged:
        return jsonify({"msg": "Coche agregado correctamente", "car_id": str(result.inserted_id)}), 201
    else:
        return jsonify({"msg": "Error al agregar coche"}), 400

#Endpoint para ver coches de usuario
@app.route('/get_cars', methods=['GET'])
@jwt_required()
def get_cars():
    # Obtener el ID del usuario del token JWT y convertir a ObjectId
    user_id = ObjectId(get_jwt_identity())  

    # Consultar la base de datos para obtener los coches asociados al usuario
    cars = mongo.db.cars.find({"user_id": user_id})

    # Convertir los resultados a una lista de diccionarios
    car_list = []
    for car in cars:
        car['_id'] = str(car['_id'])  # Convertir el ObjectId a string
        car['user_id'] = str(car['user_id'])  # Convertir user_id a string si es necesario
        car_list.append(car)

    return jsonify(car_list), 200
#Endpoint para eliminar coche
@app.route('/delete_car/<car_id>', methods=['DELETE'])
@jwt_required()
def delete_car(car_id):
    # Obtener el ID del usuario del token JWT
    user_id = ObjectId(get_jwt_identity())

    # Verificar si el coche existe y pertenece al usuario
    car = mongo.db.cars.find_one({"_id": ObjectId(car_id), "user_id": user_id})

    if not car:
        return jsonify({"msg": "Coche no encontrado o no pertenece al usuario"}), 404

    # Eliminar el coche
    result = mongo.db.cars.delete_one({"_id": ObjectId(car_id)})

    if result.deleted_count == 1:
        return jsonify({"msg": "Coche eliminado correctamente"}), 200
    else:
        return jsonify({"msg": "Error al eliminar el coche"}), 400


#Endpoint para actualizar coche
@app.route('/update_car/<car_id>', methods=['PUT'])
@jwt_required()
def update_car(car_id):
    # Obtener el ID del usuario del token JWT
    user_id = ObjectId(get_jwt_identity())
    
    data = request.get_json()
    modelo = data.get('modelo')
    anio = data.get('año')
    color = data.get('color')
    placas = data.get('placas')

    # Verificar si el coche existe y pertenece al usuario
    car = mongo.db.cars.find_one({"_id": ObjectId(car_id), "user_id": user_id})

    if not car:
        return jsonify({"msg": "Coche no encontrado o no pertenece al usuario"}), 404

    # Actualizar los datos del coche
    update_data = {}
    if modelo:
        update_data["modelo"] = modelo
    if anio:
        update_data["año"] = anio
    if color:
        update_data["color"] = color
    if placas:
        update_data["placas"] = placas

    # Si no hay datos para actualizar, devolver un error
    if not update_data:
        return jsonify({"msg": "No se proporcionaron datos para actualizar"}), 400

    result = mongo.db.cars.update_one({"_id": ObjectId(car_id)}, {"$set": update_data})

    if result.modified_count == 1:
        return jsonify({"msg": "Coche actualizado correctamente"}), 200
    else:
        return jsonify({"msg": "Error al actualizar el coche"}), 400









# En Python, cada archivo tiene una variable especial llamada _name_.
# Si el archivo se está ejecutando directamente (no importado como un módulo en otro archivo), 
# _name_ se establece en '_main_'.
# Esta condición verifica si el archivo actual es el archivo principal que se está ejecutando. 
# Si es así, ejecuta el bloque de código dentro de la condición.
# app.run() inicia el servidor web de Flask.
# El argumento debug=True  inicia el servidor web de desarrollo de Flask con el modo de 
# depuración activado, # lo que permite ver errores detallados y reiniciar automáticamente
# el servidor cuando se realizan cambios en el código. (SERIA COMO EL NODEMON)
if __name__ == '__main__':
    app.run(debug=True)