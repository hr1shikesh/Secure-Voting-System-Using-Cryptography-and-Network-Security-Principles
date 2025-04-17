import sqlite3
import json
import ssl
import socket
import threading
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from crypto_utils import CryptoManager

class VotingServer:
    def __init__(self):
        self.crypto = CryptoManager()
        self.conn = sqlite3.connect('voters.db', check_same_thread=False)
        self.lock = threading.Lock()
        self._create_tables()
        self.load_candidates()
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain('certs/server.crt', 'certs/server.key')
        self.start_server()

    def _create_tables(self):
        with self.lock:
            self.conn.execute('''CREATE TABLE IF NOT EXISTS voters (
                aadhaar TEXT PRIMARY KEY,
                full_name TEXT,
                public_key TEXT,
                hashed_pwd TEXT,
                salt TEXT
            )''')
            
            self.conn.execute('''CREATE TABLE IF NOT EXISTS votes (
                position TEXT,
                candidate_id TEXT,
                voter_id TEXT,
                signature TEXT,
                hmac TEXT,
                PRIMARY KEY (position, voter_id)
            )''')
            self.conn.commit()

    def load_candidates(self):
        with open('candidates.json') as f:
            self.candidates = json.load(f)

    def start_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', 5000))
        sock.listen(5)
        print("Secure server listening...")
        while True:
            client, addr = sock.accept()
            ssl_client = self.context.wrap_socket(client, server_side=True)
            threading.Thread(target=self.handle_client, args=(ssl_client,)).start()

    def handle_client(self, client):
        try:
            data = client.recv(4096).decode()
            request = json.loads(data)
            response = {"success": False}

            if request['action'] == 'register':
                response = self.handle_registration(request)
            elif request['action'] == 'authenticate':
                response = self.handle_authentication(request)
            elif request['action'] == 'get_candidates':
                response = self.handle_get_candidates()
            elif request['action'] == 'vote':
                response = self.handle_vote(request)
            elif request['action'] == 'tally':
                response = self.handle_tally()
            elif request['action'] == 'get_public_key':
                response = self.handle_get_public_key(request)

            client.send(json.dumps(response).encode())
        except Exception as e:
            client.send(json.dumps({"success": False, "error": str(e)}).encode())
        finally:
            client.close()

    def handle_get_public_key(self, request):
        try:
            cursor = self.conn.execute(
                "SELECT public_key FROM voters WHERE aadhaar=?", 
                (request['aadhaar'],)
                )
            result = cursor.fetchone()
            return {"success": bool(result), "public_key": result[0] if result else None}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_registration(self, request):
        try:
            aadhaar = request['aadhaar']
            full_name = request['full_name']
            password = request['password']
            
            hashed_pwd, salt = self.crypto.hash_password(password)
            voter_keys = self.crypto.generate_voter_keys()
            
            with self.lock:
                self.conn.execute("INSERT INTO voters VALUES (?, ?, ?, ?, ?)",
                                (aadhaar, full_name, voter_keys['public'], hashed_pwd, salt))
                self.conn.commit()
            
            return {"success": True, "private_key": voter_keys['private']}
        except sqlite3.IntegrityError:
            return {"success": False, "error": "Voter already registered"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_vote(self, request):
        try:
            iv = bytes.fromhex(request['iv'])
            ciphertext = bytes.fromhex(request['ciphertext'])
            tag = bytes.fromhex(request['tag'])
            ephemeral_pub_key = request['ephemeral_pub_key']
            signature = bytes.fromhex(request['signature'])
            hmac_received = bytes.fromhex(request['hmac'])
            
            with self.lock:
                cursor = self.conn.execute(
                    "SELECT public_key, salt FROM voters WHERE aadhaar=?", 
                    (request['voter_id'],))
                result = cursor.fetchone()
            
            if not result:
                return {"success": False, "error": "Voter not found"}
            
            public_key, salt_hex = result
            salt = bytes.fromhex(salt_hex)
            
            # Verify HMAC
            hmac_key = PBKDF2(request['voter_id'].encode(), salt, dkLen=32, count=1000000)
            hmac_calculated = HMAC.new(hmac_key, ciphertext, SHA256).digest()
            if hmac_calculated != hmac_received:
                return {"success": False, "error": "HMAC mismatch"}
            
            # Verify Signature
            if not self.crypto.verify_signature(ciphertext, signature, public_key):
                return {"success": False, "error": "Invalid signature"}
            
            # Insert vote
            with self.lock:
                self.conn.execute("INSERT INTO votes VALUES (?, ?, ?, ?, ?)",
                                (request['position'], request['candidate_id'], 
                                 request['voter_id'], request['signature'], request['hmac']))
                self.conn.commit()
            
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_authentication(self, request):
        try:
            cursor = self.conn.execute(
                "SELECT hashed_pwd, salt FROM voters WHERE aadhaar=?",
                (request['aadhaar'],))
            result = cursor.fetchone()
            
            if not result:
                return {"success": False, "error": "Voter not registered"}
            
            stored_hash, salt = result
            if self.crypto.verify_password(request['password'], stored_hash, salt):
                return {"success": True, "salt": salt}
            return {"success": False, "error": "Invalid credentials"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def handle_get_candidates(self):
        return {"success": True, "candidates": self.candidates}

    def handle_tally(self):
        results = {}
        with self.lock:
            for position in self.candidates.keys():
                cursor = self.conn.execute(
                    "SELECT candidate_id, COUNT(*) FROM votes WHERE position=? GROUP BY candidate_id",
                    (position,))
                results[position] = {str(row[0]): row[1] for row in cursor.fetchall()}
        return {"success": True, "results": results}

if __name__ == "__main__":
    server = VotingServer()