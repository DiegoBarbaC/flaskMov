from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from model import mongo, init_db
from config import config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt
from flask_jwt_extended import get_jwt_identity
from bson import ObjectId
from datetime import timedelta, datetime



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
    

# Endpoint para actualizar la información del usuario
@app.route('/update_profile', methods=['PUT'])
@jwt_required()
def update_profile():
    # Obtener el ID del usuario del token JWT
    user_id = get_jwt_identity()

    # Obtener los datos enviados en la solicitud
    data = request.get_json()
    username = data.get('username')
    
    password = data.get('password')

    # Crear un diccionario para almacenar los campos a actualizar
    update_data = {}

    # Verificar si se proporcionaron campos para actualizar
    if username:
        update_data['username'] = username
    
    if password:
        # Si se proporciona una nueva contraseña, se debe hashear
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        update_data['password'] = hashed_password

    # Si no hay datos para actualizar, devolver un error
    if not update_data:
        return jsonify({"msg": "No se proporcionaron datos para actualizar"}), 400

    # Actualizar la información del usuario en la base de datos
    result = mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": update_data})

    # Verificar si se realizó la actualización
    if result.modified_count > 0:
        return jsonify({"msg": "Perfil actualizado correctamente"}), 200
    else:
        return jsonify({"msg": "No se pudo actualizar el perfil"}), 400

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
        
        return jsonify(accessToken=access_token),200
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
    # Obtener el ID del usuario del token JWT
    user_id = ObjectId(get_jwt_identity())
    # Validar campos requeridos
    required_fields = ['origen', 'destino', 'hora_inicio']
    for field in required_fields:
        if not data.get(field):
            return jsonify({"msg": f"El campo {field} es requerido"}), 400

    pasajero_id = user_id  # ID del usuario pasajero
    conductor_id = data.get('conductor_id')  # ID del usuario conductor
    destino = data.get('destino')
    origen = data.get('origen')
    coords_origen = data.get('coords_origen')  # Diccionario con {lat, long}
    coords_destino = data.get('coords_destino')  # Diccionario con {lat, long}
    hora_inicio = data.get('hora_inicio')  # Formato de fecha/hora
    coche_id = data.get('coche_id')

    # Crear el viaje
    nuevo_viaje = {
        "pasajero_id": ObjectId(pasajero_id),
        "conductor_id": ObjectId(conductor_id) if conductor_id else None,
        "destino": destino,
        "origen": origen,
        "coords_origen": coords_origen if coords_origen else None,
        "coords_destino": coords_destino if coords_destino else None,
        "hora_inicio": hora_inicio,
        "coche_id": ObjectId(coche_id) if coche_id else None
    }

    result = mongo.db.rides.insert_one(nuevo_viaje)
    if result.acknowledged:
        ride_created = mongo.db.rides.find_one({"_id": result.inserted_id})
        return jsonify({"msg": "Viaje solicitado correctamente, espera a que sea aceptado"}), 201
        # Convertir ObjectId a string para la respuesta JSON
        ride_response = {
            "id": str(ride_created["_id"]),
            "pasajero_id": str(ride_created["pasajero_id"]),
            "conductor_id": str(ride_created["conductor_id"]) if ride_created.get("conductor_id") else None,
            "destino": ride_created["destino"],
            "origen": ride_created["origen"],
            "coords_origen": ride_created.get("coords_origen"),
            "coords_destino": ride_created.get("coords_destino"),
            "hora_inicio": ride_created["hora_inicio"],
            "estado": ride_created["estado"],
            "fecha_creacion": ride_created["fecha_creacion"].isoformat()
        }
        return jsonify({
            "msg": "Viaje solicitado correctamente",
            "ride": ride_response
        }), 201
    else:
        return jsonify({"msg": "Error al crear viaje"}), 400

#Endpoint para ver todos los viajes de un usuario
@app.route('/get_user_rides', methods=['GET'])
@jwt_required()
def get_user_rides():
    # Obtener el ID del usuario del token JWT
    user_id = get_jwt_identity()

    try:
        # Buscar viajes donde el usuario es el pasajero o el conductor
        rides = mongo.db.rides.find({
            "$or": [
                {"pasajero_id": ObjectId(user_id)},
                {"conductor_id": ObjectId(user_id)}
            ]
        }).sort("hora_inicio", -1)  # Ordenar por hora de inicio, más recientes primero

        # Convertir los resultados a una lista de diccionarios
        ride_list = []
        for ride in rides:
            # Obtener información del pasajero
            pasajero = mongo.db.users.find_one({"_id": ride['pasajero_id']})
            pasajero_info = {
                "id": str(pasajero['_id']),
                "email": pasajero['email']
            } if pasajero else None

            # Obtener información del conductor si existe
            conductor_info = None
            if ride.get('conductor_id'):
                conductor = mongo.db.users.find_one({"_id": ride['conductor_id']})
                if conductor:
                    conductor_info = {
                        "id": str(conductor['_id']),
                        "email": conductor['email']
                    }

            # Construir el objeto de ride con información detallada
            ride_detail = {
                'id': str(ride['_id']),
                'pasajero': pasajero_info,
                'conductor': conductor_info,
                'origen': ride['origen'],
                'destino': ride['destino'],
                'coords_origen': ride.get('coords_origen'),
                'coords_destino': ride.get('coords_destino'),
                'hora_inicio': ride['hora_inicio'],
                'estado': ride.get('estado', 'pendiente'),
                'coche_id': str(ride['coche_id']) if ride.get('coche_id') else None
            }
            ride_list.append(ride_detail)

        return jsonify({
            "success": True,
            "rides": ride_list
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "msg": "Error al obtener los viajes",
            "error": str(e)
        }), 400

#Endpoint para ver todos los viajes disponibles (sin conductor asignado)
@app.route('/get_available_rides', methods=['GET'])
@jwt_required()
def get_available_rides():
    try:
        # Obtener el ID del usuario actual
        current_user_id = get_jwt_identity()

        # Buscar viajes sin conductor asignado y que no sean del usuario actual
        rides = mongo.db.rides.find({
            "conductor_id": None,
            "pasajero_id": {"$ne": ObjectId(current_user_id)},
            "estado": "pendiente"
        }).sort("hora_inicio", 1)  # Ordenar por hora de inicio, más próximos primero

        ride_list = []
        for ride in rides:
            # Obtener información del pasajero
            pasajero = mongo.db.users.find_one({"_id": ride['pasajero_id']})
            pasajero_info = {
                "id": str(pasajero['_id']),
                "email": pasajero['email']
            } if pasajero else None

            ride_detail = {
                'id': str(ride['_id']),
                'pasajero': pasajero_info,
                'origen': ride['origen'],
                'destino': ride['destino'],
                'coords_origen': ride.get('coords_origen'),
                'coords_destino': ride.get('coords_destino'),
                'hora_inicio': ride['hora_inicio'],
                'estado': ride.get('estado', 'pendiente')
            }
            ride_list.append(ride_detail)

        return jsonify({
            "success": True,
            "rides": ride_list
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "msg": "Error al obtener los viajes disponibles",
            "error": str(e)
        }), 400


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
    

# Endpoint para obtener detalles de un viaje específico
@app.route('/ride/<ride_id>', methods=['GET'])
@jwt_required()
def get_ride_details(ride_id):
    # Obtener el ID del usuario del token JWT
    user_id = get_jwt_identity()

    # Buscar el viaje por ID
    ride = mongo.db.rides.find_one({"_id": ObjectId(ride_id)})

    if not ride:
        return jsonify({"msg": "Ride no encontrado"}), 404

    # Verificar si el usuario es el pasajero o el conductor del viaje
    if ride['pasajero_id'] != ObjectId(user_id) and ride['conductor_id'] != ObjectId(user_id):
        return jsonify({"msg": "No tienes permiso para ver este viaje"}), 403

    # Convertir el ObjectId a string para la respuesta
    ride['_id'] = str(ride['_id'])
    ride['pasajero_id'] = str(ride['pasajero_id'])
    ride['conductor_id'] = str(ride['conductor_id'])
    ride['coche_id'] = str(ride['coche_id'])

    return jsonify(ride), 200



@app.route('/ride_request', methods=['POST'])
@jwt_required()
def create_ride_request():
    try:
        data = request.get_json()
        pasajero_id = get_jwt_identity()  # Obtenemos el ID del pasajero del token
        
        if not data or 'origen' not in data or 'destino' not in data:
            return jsonify({"msg": "Faltan datos requeridos"}), 400

        # Coordenadas por default (UNAM)
        coords_origen_default = {
            "lat": 19.3321,
            "lng": -99.1870
        }

        # Crear la solicitud de viaje
        nueva_solicitud = {
            "pasajero_id": ObjectId(pasajero_id),
            "origen": data['origen'],
            "destino": data['destino'],
            "coords_origen": coords_origen_default,
            "fecha_solicitud": datetime.utcnow()
        }

        result = mongo.db.ride_requests.insert_one(nueva_solicitud)
        
        if result.acknowledged:
            return jsonify({
                "msg": "Solicitud creada correctamente",
                "request_id": str(result.inserted_id)
            }), 201
        else:
            return jsonify({"msg": "Error al crear la solicitud"}), 500
            
    except Exception as e:
        print(f"Error en create_ride_request: {str(e)}")  # Para debugging
        return jsonify({"msg": "Error interno del servidor"}), 500

@app.route('/ride_requests', methods=['GET'])
@jwt_required()
def get_ride_requests():
    try:
        # Obtener el ID del usuario actual del token
        current_user_id = get_jwt_identity()
        
        # Buscar todas las solicitudes excepto las del usuario actual
        solicitudes = list(mongo.db.ride_requests.find({
            "pasajero_id": {"$ne": ObjectId(current_user_id)}
        }))
        
        # Convertir los resultados a una lista de diccionarios
        solicitudes_list = []
        for solicitud in solicitudes:
            # Obtener información del pasajero
            pasajero = mongo.db.users.find_one({"_id": solicitud['pasajero_id']})
            
            solicitud_formatted = {
                '_id': str(solicitud['_id']),
                'pasajero_id': str(solicitud['pasajero_id']),
                'origen': solicitud['origen'],
                'destino': solicitud['destino'],
                'coords_origen': solicitud['coords_origen'],
                'fecha_solicitud': solicitud['fecha_solicitud'].isoformat(),
                # Agregar nombre del pasajero pero no información sensible
                'pasajero_nombre': pasajero.get('username') if pasajero else 'Usuario'
            }
            solicitudes_list.append(solicitud_formatted)

        return jsonify(solicitudes_list), 200
    except Exception as e:
        print(f"Error en get_ride_requests: {str(e)}")
        return jsonify({"msg": "Error al obtener las solicitudes"}), 500




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