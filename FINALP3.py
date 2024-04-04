from http.server import HTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from datetime import datetime, timedelta, timezone
from jwt.utils import base64url_encode, bytes_from_int
from calendar import timegm
import sqlite3
import json
import jwt
import uuid
from argon2 import PasswordHasher


class RequestHandler(BaseHTTPRequestHandler):
    # JSON Web Keys Storage
    JWKS = {"keys": []}

    # Methods for HTTP request types
    def do_PUT(self):  
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):  
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):  
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):  
        self.send_response(405)
        self.end_headers()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.end_headers()
            curs = db.cursor()

            select = "SELECT * FROM keys WHERE exp > ?;"
            curs.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
            rows = curs.fetchall()

            for row in rows:
                expiry = row[2]
                privt_key_bytes = row[1]
                keyID = str(row[0])
                privt_key = load_pem_private_key(privt_key_bytes, None)
                publc_key = privt_key.public_key()

                JWK = {
                    "kid": keyID,
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "n": base64url_encode(
                        bytes_from_int(publc_key.public_numbers().n)
                    ).decode(
                        "UTF-8"
                    ),  
                    "e": base64url_encode(
                        bytes_from_int(publc_key.public_numbers().e)
                    ).decode(
                        "UTF-8"
                    ),  
                }
                if not expiry <= timegm(datetime.now(tz=timezone.utc).timetuple()):
                    self.JWKS["keys"].append(JWK)

            self.wfile.write(json.dumps(self.JWKS, indent=1).encode("UTF-8"))
            return
        else:
            self.send_response(405)  
            self.end_headers()
            return

    def do_POST(self):
        if (self.path == "/auth" or self.path == "/auth?expired=true" or self.path == "/auth?expired=false"):

            expired = False
            if self.path == "/auth?expired=true":
                expired = True
            self.send_response(200)
            self.end_headers()
            curs = db.cursor()

            if expired:
                select = "SELECT kid, key, exp FROM keys WHERE exp <= ?;"
            else:
                select = "SELECT * FROM keys WHERE exp > ?;"
            curs.execute(select, (timegm(datetime.now(tz=timezone.utc).timetuple()),))
            key_row = curs.fetchone()

            expiry = key_row[2]
            privt_key_bytes = key_row[1]
            keyID = str(key_row[0])
            jwt_token = jwt.encode(
                {"exp": expiry},
                privt_key_bytes,
                algorithm="RS256",
                headers={"kid": keyID},
            )
            self.wfile.write(bytes(jwt_token, "UTF-8"))

               
            ### Log authentication request into the database
            
            # Getting IP
            request_ip = self.client_address[0]

            # Get the length of the incoming request body
            content_length = int(self.headers['Content-Length'])
            # Read and parse the request body
            post_data = json.loads(self.rfile.read(content_length))

            # Extract username and email from request body
            username = post_data.get('username', '')

            # GETTING user_id from database using userName

            curr = db.cursor()
            curr.execute("SELECT id FROM users WHERE username = ?", (username,))
            rows = curr.fetchall()

            id_of_username = ""

            for row in rows:
                id_of_username = row[0]
                


            curr.close()

            db.execute('''INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)''', (request_ip, id_of_username))
            db.commit()
            
            ####


            return
        

        elif (self.path == "/register"):

            # Get the length of the incoming request body
            content_length = int(self.headers['Content-Length'])
            # Read and parse the request body
            post_data = json.loads(self.rfile.read(content_length))

            # Extract username and email from request body
            username = post_data.get('username', '')
            email = post_data.get('email', '')

            # Generate a secure password using UUIDv4
            generated_password = str(uuid.uuid4())

            # Set response status code
            self.send_response(201)  # Created

            # Set headers
            self.send_header('Content-type', 'application/json')
            self.end_headers()

            # Create response JSON
            response_data = {'password': generated_password}

            # Convert response JSON to bytes and send
            self.wfile.write(json.dumps(response_data).encode('utf-8'))


            #### HASHING PASSWORDS
            # Hash the generated password using Argon2
            ph = PasswordHasher()
            hashed_password  = ph.hash(generated_password)


            #Storing the user details in users table

            insert = "INSERT INTO users (username, password_hash, email) VALUES(?, ?, ?);"
            db.execute(insert, (username, hashed_password, email))
            db.commit()
            
            
            return
        

        else:
            self.send_response(405)  
            self.end_headers()
            return

# Create HTTP server 
hostName = "localhost"
serverPort = 8080



# Connect to the database and create the keys table 
db = sqlite3.connect("totally_not_my_privateKeys.db")
db.execute("CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);")

# Generate key pairs and insert them into the database

for i in range(5):
    privt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privt_key_bytes = privt_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if i % 2 == 0:
        expiry = datetime.now(tz=timezone.utc) + timedelta(0, -3600, 0)
    else:
        expiry = datetime.now(tz=timezone.utc) + timedelta(0, 3600, 0)

    insert = "INSERT INTO keys (key, exp) VALUES(?, ?);"
    db.execute(insert, (privt_key_bytes, timegm(expiry.timetuple())))
db.commit()




############## Writing the user table
db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,email TEXT UNIQUE,date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,last_login TIMESTAMP);") 

db.commit()




############## Writing the auth_logs table
db.execute("CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL ,request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP ,user_id INTEGER ,FOREIGN KEY(user_id) REFERENCES users(id));") 

db.commit()



if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), RequestHandler)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

