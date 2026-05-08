import json
import random
import hashlib
import mysql.connector
import base64
import shutil
from datetime import datetime
from pathlib import Path
from bottle import route, run, template, post, request, static_file



def loadDatabaseSettings(pathjs):
	pathjs = Path(pathjs)
	sjson = False
	if pathjs.exists():
		with pathjs.open() as data:
			sjson = json.load(data)
	return sjson
	
"""
function loadDatabaseSettings(pathjs):
	string = file_get_contents(pathjs);
	json_a = json_decode(string, true);
	return json_a;

"""
def getToken():
	tiempo = datetime.now().timestamp()
	numero = random.random()
	cadena = str(tiempo) + str(numero)
	numero2 = random.random()
	cadena2 = str(numero)+str(tiempo)+str(numero2)
	m = hashlib.sha1()
	m.update(cadena.encode())
	P = m.hexdigest()
	m = hashlib.md5()
	m.update(cadena.encode())
	Q = m.hexdigest()
	return f"{P[:20]}{Q[20:]}"

"""
*/ 
# Registro
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 *		"email": "XXX",
 * 		"password": "XXX"
 * 
 * */
"""
@post('/Registro')
def Registro():
    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )
    
    ####/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
        
    R = 'uname' in request.json and 'email' in request.json and 'password' in request.json
    if not R:
        return {"R":-1}

    # --- PARCHE DE SEGURIDAD: Hashear contraseña con SHA-256 en lugar de MD5 ---
    password_plana = request.json["password"]
    password_hash = hashlib.sha256(password_plana.encode()).hexdigest()
    
    R = False
    try:
        with db.cursor() as cursor:
            # Consulta parametrizada (%s) para evitar Inyección SQL
            query = 'INSERT INTO Usuario VALUES(null, %s, %s, %s)'
            valores = (request.json["uname"], request.json["email"], password_hash)
            
            cursor.execute(query, valores)
            R = cursor.lastrowid
            db.commit()
        db.close()
    except Exception as e:
        print(e) 
        return {"R":-2}
    return {"R":0,"D":R}




"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 *		"uname": "XXX",
 * 		"password": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Login')
def Login():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'uname' in request.json  and 'password' in request.json
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# TODO Control de error de la DB
	R = False
	try:
		with db.cursor() as cursor:
			print(f'Select id from  Usuario where uname ="{request.json["uname"]}" and password = md5("{request.json["password"]}")')
			cursor.execute(f'Select id from  Usuario where uname ="{request.json["uname"]}" and password = md5("{request.json["password"]}")');
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
	
	
	if not R:
		db.close()
		return {"R":-3}
	
	T = getToken();
	#file_put_contents('/tmp/log','insert into AccesoToken values('.R[0].',"'.T.'",now())');
	with open("/tmp/log","a") as log:
		log.write(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"\n')
		log.write(f'insert into AccesoToken values({R[0][0]},"{T}",now())\n')
	
	
	try:
		with db.cursor() as cursor:
			cursor.execute(f'Delete from AccesoToken where id_Usuario = "{R[0][0]}"');
			cursor.execute(f'insert into AccesoToken values({R[0][0]},"{T}",now())');
			db.commit()
			db.close()
			return {"R":0,"D":T}
	except Exception as e:
		print(e)
		db.close()
		return {"R":-4}

"""
/*
 * Este subir imagen recibe un JSON con el siguiente formato
 * 
 * 
 * 		"token: "XXX"
 *		"name": "XXX",
 * 		"data": "XXX",
 * 		"ext": "PNG"
 * 
 * 
 * Debe retornar codigo de estado
 * */
"""
@post('/Imagen')
def Imagen():
    # Directorio
    tmp = Path('tmp')
    if not tmp.exists():
        tmp.mkdir()
    img = Path('img')
    if not img.exists():
        img.mkdir()
    
    ###/ obtener el cuerpo de la peticion
    if not request.json:
        return {"R":-1}
    ######/
    R = 'name' in request.json  and 'data' in request.json and 'ext' in request.json  and 'token' in request.json
    if not R:
        return {"R":-1}

    # --- PARCHE DE SEGURIDAD 1: Lista Blanca de Extensiones ---
    ext_permitidas = ['png', 'jpg', 'jpeg', 'gif']
    ext_usuario = str(request.json['ext']).lower()
    
    if ext_usuario not in ext_permitidas:
        return {"R":-5} # Rechazar si no es una imagen válida

    dbcnf = loadDatabaseSettings('db.json')
    db = mysql.connector.connect(
        host='localhost', port = dbcnf['port'],
        database = dbcnf['dbname'],
        user = dbcnf['user'],
        password = dbcnf['password']
    )

    TKN = request.json['token']
    
    # Validar token (Parchado contra Inyección SQL)
    try:
        with db.cursor() as cursor:
            cursor.execute('SELECT id_Usuario FROM AccesoToken WHERE token = %s', (TKN,))
            res_token = cursor.fetchall()
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-2}
    
    if not res_token:
        db.close()
        return {"R":-1}
        
    id_Usuario = res_token[0][0]
    
    with open(f'tmp/{id_Usuario}',"wb") as imagen:
        imagen.write(base64.b64decode(request.json['data'].encode()))
    
    # Guardar info del archivo (Parchado contra Inyección SQL)
    try:
        with db.cursor() as cursor:
            # 1. Insertar el nombre seguro
            cursor.execute('INSERT INTO Imagen VALUES(null, %s, "img/", %s)', (request.json["name"], id_Usuario))
            
            # 2. Buscar el id recien creado
            cursor.execute('SELECT max(id) FROM Imagen WHERE id_Usuario = %s', (id_Usuario,))
            res_id = cursor.fetchall()
            idImagen = res_id[0][0]
            
            # 3. Actualizar la ruta con la extensión validada
            ruta_final = f'img/{idImagen}.{ext_usuario}'
            cursor.execute('UPDATE Imagen SET ruta = %s WHERE id = %s', (ruta_final, idImagen))
            db.commit()
            
            # Mover archivo a su nueva locacion
            shutil.move(f'tmp/{id_Usuario}', ruta_final)
            return {"R":0,"D":idImagen}
    except Exception as e: 
        print(e)
        db.close()
        return {"R":-3}
	
"""
/*
 * Este Registro recibe un JSON con el siguiente formato
 * 
 * : 
 * 		"token: "XXX",
 * 		"id": "XXX"
 * 
 * 
 * Debe retornar un Token 
 * */
"""

@post('/Descargar')
def Descargar():
	dbcnf = loadDatabaseSettings('db.json');
	db = mysql.connector.connect(
		host='localhost', port = dbcnf['port'],
		database = dbcnf['dbname'],
		user = dbcnf['user'],
		password = dbcnf['password']
	)
	
	
	###/ obtener el cuerpo de la peticion
	if not request.json:
		return {"R":-1}
	######/
	R = 'token' in request.json and 'id' in request.json  
	# TODO checar si estan vacio los elementos del json
	if not R:
		return {"R":-1}
	
	# TODO validar correo en json
	# Comprobar que el usuario sea valido
	TKN = request.json['token'];
	idImagen = request.json['id'];
	
	R = False
	try:
		with db.cursor() as cursor:
			cursor.execute('select id_Usuario from AccesoToken where token = "'+TKN+'"');
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-2}
		
	
	
	# Buscar imagen y enviarla
	
	try:
		with db.cursor() as cursor:
			cursor.execute('Select name,ruta from  Imagen where id = '+str(idImagen));
			R = cursor.fetchall()
	except Exception as e: 
		print(e)
		db.close()
		return {"R":-3}
	print(Path("img").resolve(),R[0][1])
	return static_file(R[0][1],Path(".").resolve())

if __name__ == '__main__':
    run(host='localhost', port=8080, debug=True)
