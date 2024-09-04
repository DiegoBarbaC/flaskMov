from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from model import mongo, init_db
from config import config
from bson.json_util import ObjectId
from flask_bcrypt import Bcrypt
app=Flask(__name__)
app.config.from_object(config)

bcrypt = Bcrypt(app)
jwt= JWTManager(app)

init_db(app)

#Definir endpoint para registrar usuario
@app.route('/register', methods=['POST'])
def register():
    data=request.get_json()
    email = data.get('email')
    password = data.get('password')

    if(mongo.db.users.findOne({"email":email})):
        return jsonify ({"msg":"Ese usuario ya existe"}), 400
    
    hashed_

if (__name__)=='__main__':
    app.run(debug=True)
