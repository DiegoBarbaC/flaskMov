
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from model import mongo, init_db
from config import config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId
from datetime import timedelta



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
        expires = timedelta(days=1)
        access_token = create_access_token(identity=str(user["_id"]), expires_delta=expires)
        
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


#Endpoint para crear ride
@app.route('/create_ride', methods=['POST'])
@jwt_required()
def create_ride():
    data = request.get_json()

    pasajero_id = data.get('pasajero_id')  # ID del usuario pasajero
    conductor_id = data.get('conductor_id')  # ID del usuario conductor
    destino = data.get('destino')
    origen = data.get('origen')
    coords_origen = data.get('coords_origen')  # Diccionario con {lat, long}
    coords_destino = data.get('coords_destino')  # Diccionario con {lat, long}
    hora_inicio = data.get('hora_inicio')  # Formato de fecha/hora
    coche_id = data.get('coche_id')

    # Verificar que el pasajero, conductor y coche existan
    pasajero = mongo.db.users.find_one({"_id": ObjectId(pasajero_id)})
    conductor = mongo.db.users.find_one({"_id": ObjectId(conductor_id)})
    coche = mongo.db.cars.find_one({"_id": ObjectId(coche_id)})

    if not pasajero or not conductor or not coche:
        return jsonify({"msg": "Pasajero, conductor o coche no encontrados"}), 404

    # Crear el viaje
    nuevo_viaje = {
        "pasajero_id": ObjectId(pasajero_id),
        "conductor_id": ObjectId(conductor_id),
        "destino": destino,
        "origen": origen,
        "coords_origen": coords_origen,
        "coords_destino": coords_destino,
        "hora_inicio": hora_inicio,
        "coche_id": ObjectId(coche_id)
    }

    result = mongo.db.rides.insert_one(nuevo_viaje)
    if result.acknowledged:
        return jsonify({"msg": "Viaje creado correctamente", "ride_id": str(result.inserted_id)}), 201
    else:
        return jsonify({"msg": "Error al crear viaje"}), 400

#Endpoint para ver todos los viajes de un usuario
@app.route('/get_user_rides', methods=['GET'])
@jwt_required()
def get_user_rides():
    # Obtener el ID del usuario del token JWT
    user_id = get_jwt_identity()

    # Buscar viajes donde el usuario es el pasajero o el conductor
    rides = mongo.db.rides.find({
        "$or": [
            {"pasajero_id": ObjectId(user_id)},
            {"conductor_id": ObjectId(user_id)}
        ]
    })

    # Convertir los resultados a una lista de diccionarios
    ride_list = []
    for ride in rides:
        ride['_id'] = str(ride['_id'])  # Convertir el ObjectId a string
        ride['pasajero_id'] = str(ride['pasajero_id'])
        ride['conductor_id'] = str(ride['conductor_id'])
        ride['coche_id'] = str(ride['coche_id'])
        ride_list.append(ride)

    # Devolver la lista de viajes en formato JSON
    return jsonify(ride_list), 200

#Endpoint para actualizar ride
@app.route('/update_ride/<ride_id>', methods=['PUT'])
@jwt_required()
def update_ride(ride_id):
    # Obtener los datos enviados en la solicitud
    data = request.get_json()

    # Verificar si el viaje existe
    ride = mongo.db.rides.find_one({"_id": ObjectId(ride_id)})
    if not ride:
        return jsonify({"msg": "Ride no encontrado"}), 404

    # Actualizar los campos permitidos si están presentes en el body del request
    update_fields = {}

    if 'pasajero_id' in data:
        update_fields['pasajero_id'] = ObjectId(data['pasajero_id'])
    if 'conductor_id' in data:
        update_fields['conductor_id'] = ObjectId(data['conductor_id'])
    if 'destino' in data:
        update_fields['destino'] = data['destino']
    if 'origen' in data:
        update_fields['origen'] = data['origen']
    if 'coords_origen' in data:
        update_fields['coords_origen'] = data['coords_origen']
    if 'coords_destino' in data:
        update_fields['coords_destino'] = data['coords_destino']
    if 'hora_inicio' in data:
        update_fields['hora_inicio'] = data['hora_inicio']
    if 'coche_id' in data:
        update_fields['coche_id'] = ObjectId(data['coche_id'])

    # Si no hay campos para actualizar, devolver error
    if not update_fields:
        return jsonify({"msg": "No se proporcionaron campos válidos para actualizar"}), 400

    # Realizar la actualización en la base de datos
    result = mongo.db.rides.update_one(
        {"_id": ObjectId(ride_id)},
        {"$set": update_fields}
    )

    # Verificar si se realizó la actualización
    if result.modified_count > 0:
        return jsonify({"msg": "Ride actualizado correctamente"}), 200
    else:
        return jsonify({"msg": "No se pudo actualizar el ride"}), 400


#Endpoint para eliminar/cancelar ride
@app.route('/delete_ride/<ride_id>', methods=['DELETE'])
@jwt_required()
def delete_ride(ride_id):
    # Verificar si el viaje existe
    ride = mongo.db.rides.find_one({"_id": ObjectId(ride_id)})
    if not ride:
        return jsonify({"msg": "Ride no encontrado"}), 404

    # Eliminar el ride de la base de datos
    result = mongo.db.rides.delete_one({"_id": ObjectId(ride_id)})

    # Verificar si se eliminó correctamente
    if result.deleted_count > 0:
        return jsonify({"msg": "Ride eliminado correctamente"}), 200
    else:
        return jsonify({"msg": "No se pudo eliminar el ride"}), 400












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