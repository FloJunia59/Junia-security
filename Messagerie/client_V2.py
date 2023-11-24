from threading import Thread
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def Send(socket, public_key):
    while True:
        msg = input("Client: ")  # Saisir un message depuis la console
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_msg = cipher.encrypt(msg.encode('utf-8'))
        
        print(f"\nClient - Message envoyé (chiffré) : {encrypted_msg}")
        socket.send(encrypted_msg)

def Reception(socket, private_key):
    while True:
        encrypted_msg = socket.recv(1024)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_msg = cipher.decrypt(encrypted_msg)
        
        print(f"\nClient - Message reçu (chiffré) : {encrypted_msg}", end='\n\n')
        print(f"Client - Message reçu (déchiffré) : {decrypted_msg.decode('utf-8')}", end='\n\n')

# Adresse IP et port du serveur
Host = "192.168.56.1"
Port = 6390

# Création du socket et connexion au serveur
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((Host, Port))

# Génération des clés RSA
key = RSA.generate(2048)
public_key = key.publickey()

print(f"Client - Clé publique générée : {public_key.export_key()}", end='\n\n')
socket.send(public_key.export_key())

server_public_key = RSA.import_key(socket.recv(4096))
print(f"Client - Clé publique du serveur reçue : {server_public_key.export_key()}")

# Création de threads pour l'envoi et la réception simultanés
envoi = Thread(target=Send, args=[socket, server_public_key])
recep = Thread(target=Reception, args=[socket, key])

# Démarrage des threads
envoi.start()
recep.start()
