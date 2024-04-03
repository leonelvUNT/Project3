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
                    ),  # base64 encoded Modulus
                    "e": base64url_encode(
                        bytes_from_int(publc_key.public_numbers().e)
                    ).decode(
                        "UTF-8"
                    ),  # base64 encoded Exponent
                }
                if not expiry <= timegm(datetime.now(tz=timezone.utc).timetuple()):
                    self.JWKS["keys"].append(JWK)

            self.wfile.write(json.dumps(self.JWKS, indent=1).encode("UTF-8"))
            return
        else:
            self.send_response(405)  # Handles other GET requests (Method Not Allowed)
            self.end_headers()
            return

    def do_POST(self):
        if (
            self.path == "/auth"
            or self.path == "/auth?expired=true"
            or self.path == "/auth?expired=false"
        ):
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
            return
        else:
            self.send_response(405)  # Handles other POST requests (Method Not Allowed)
            self.end_headers()
            return

# Create HTTP server 
hostName = "localhost"
serverPort = 8080



# Connect to the SQLite database and create the keys table if not exists
db = sqlite3.connect("totally_not_my_privateKeys.db")
db.execute("CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);")

# Generate key pairs and insert them into the database
print("Generating key pairs... Please wait...")
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
print("HTTP Server running on Localhost port 8080...")



if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), RequestHandler)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

