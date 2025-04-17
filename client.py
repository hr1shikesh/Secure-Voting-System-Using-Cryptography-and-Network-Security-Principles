import socket
import ssl
import json
import sys
import platform
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from crypto_utils import CryptoManager

# Platform-specific password input handling
if platform.system() == "Windows":
    import msvcrt
    def get_password(prompt):
        print(prompt, end='', flush=True)
        password = []
        while True:
            ch = msvcrt.getch().decode('utf-8')
            if ch == '\r':
                print()
                break
            elif ch == '\x08':
                if password:
                    password.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            else:
                password.append(ch)
                sys.stdout.write('*')
                sys.stdout.flush()
        return ''.join(password)
else:
    import tty
    import termios
    def get_password(prompt):
        print(prompt, end='', flush=True)
        password = []
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ('\r', '\n'):
                    print()
                    break
                elif ch == '\x7f':
                    if password:
                        password.pop()
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    password.append(ch)
                    sys.stdout.write('*')
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ''.join(password)

class VotingClient:
    def __init__(self):
        self.crypto = CryptoManager()
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.load_verify_locations('certs/server.crt')
        self.session_id = None
        self.salt = None
        self.private_key = None

    def send_request(self, request):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                ssl_sock = self.context.wrap_socket(sock, server_hostname='localhost')
                ssl_sock.connect(('localhost', 5000))
                ssl_sock.send(json.dumps(request).encode())
                return json.loads(ssl_sock.recv(4096).decode())
        except Exception as e:
            return {"success": False, "error": str(e)}

    def register(self):
        print("\nVoter Registration:")
        aadhaar = input("Aadhaar Number: ").strip()
        full_name = input("Full Name: ").strip()
        password = get_password("Password: ")
        
        response = self.send_request({
            "action": "register",
            "aadhaar": aadhaar,
            "full_name": full_name,
            "password": password
        })
        
        if response.get('success'):
            print("\nRegistration Successful!")
            self.private_key = response['private_key']
            with open(f"{aadhaar}_private.pem", "w") as f:
                f.write(self.private_key)
            print(f"Private key saved to {aadhaar}_private.pem")
        else:
            print("\nRegistration Failed:", response.get('error', 'Unknown error'))

    def authenticate(self):
        aadhaar = input("Aadhaar Number: ").strip()
        password = get_password("Password: ")
        
        response = self.send_request({
            "action": "authenticate",
            "aadhaar": aadhaar,
            "password": password
        })
        
        if response.get('success'):
            self.session_id = aadhaar
            self.salt = response.get('salt')
            try:
                with open(f"{aadhaar}_private.pem", "r") as f:
                    self.private_key = f.read().strip()
                if not self.private_key.startswith("-----BEGIN PRIVATE KEY-----"):
                    raise ValueError("Invalid key format")
                return True
            except Exception as e:
                print("Error loading private key:", str(e))
                return False
        print("Authentication Failed:", response.get('error', 'Unknown error'))
        return False

    def vote(self):
        if not self.session_id or not self.salt or not self.private_key:
            print("Please authenticate first!")
            return
            
        response = self.send_request({"action": "get_candidates"})
        if not response.get('success'):
            print("Error fetching candidates:", response.get('error'))
            return
            
        candidates = response['candidates']
        print("\nAvailable Positions:")
        for idx, pos in enumerate(candidates.keys(), 1):
            print(f"{idx}. {pos}")
        
        try:
            pos_choice = int(input("Select position: ")) - 1
            position = list(candidates.keys())[pos_choice]
            
            print(f"\nCandidates for {position}:")
            for candidate in candidates[position]:
                print(f"{candidate['id']}. {candidate['name']} ({candidate['party']})")
            
            candidate_id = int(input("Enter Candidate ID: "))
            
            pub_key_resp = self.send_request({
                "action": "get_public_key",
                "aadhaar": self.session_id
            })
            if not pub_key_resp.get('success'):
                print("Error getting public key:", pub_key_resp.get('error'))
                return
            
            vote_data = f"{position}:{candidate_id}"
            encrypted_data = self.crypto.encrypt_vote(vote_data, pub_key_resp['public_key'])
            signature = self.crypto.sign_data(encrypted_data[1], self.private_key)
            
            hmac_key = PBKDF2(
                self.session_id.encode(),
                bytes.fromhex(self.salt),
                dkLen=32,
                count=1000000
            )
            hmac = self.crypto.generate_hmac(encrypted_data[1], hmac_key)
            
            vote_response = self.send_request({
                "action": "vote",
                "position": position,
                "candidate_id": candidate_id,
                "voter_id": self.session_id,
                "iv": encrypted_data[0].hex(),
                "ciphertext": encrypted_data[1].hex(),
                "tag": encrypted_data[2].hex(),
                "ephemeral_pub_key": encrypted_data[3],
                "signature": signature.hex(),
                "hmac": hmac.hex()
            })
            
            if vote_response.get('success'):
                print("Vote cast successfully!")
            else:
                print("Voting failed:", vote_response.get('error'))
        except (ValueError, IndexError) as e:
            print("Invalid input:", str(e))

    def view_results(self):
        response = self.send_request({"action": "tally"})
        if response.get('success'):
            print("\nElection Results:")
            for position, results in response['results'].items():
                print(f"\n{position}:")
                for cid, votes in results.items():
                    print(f"Candidate {cid}: {votes} votes")
        else:
            print("Error fetching results:", response.get('error'))

    def start(self):
        while True:
            print("\n1. Register\n2. Login\n3. Vote\n4. View Results\n5. Exit")
            choice = input("Choose option: ").strip()
            
            if choice == '1':
                self.register()
            elif choice == '2':
                if self.authenticate():
                    print("Login successful!")
            elif choice == '3':
                self.vote()
            elif choice == '4':
                self.view_results()
            elif choice == '5':
                break
            else:
                print("Invalid choice!")

if __name__ == "__main__":
    client = VotingClient()
    client.start()