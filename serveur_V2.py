from threading import Thread
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def Send(client, public_key):
    while True:
        msg = input("Serveur: ")  # Saisir un message depuis la console
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_msg = cipher.encrypt(msg.encode('utf-8'))
        
        print(f"\nServeur - Message envoyé (chiffré) : {encrypted_msg}")
        client.send(encrypted_msg)

def Reception(client, private_key):
    while True:
        encrypted_msg = client.recv(1024)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_msg = cipher.decrypt(encrypted_msg)
        
        print(f"\nServeur - Message reçu (chiffré) : {encrypted_msg}", end='\n\n')
        print(f"Serveur - Message reçu (déchiffré) : {decrypted_msg.decode('utf-8')}", end='\n\n')

# Adresse IP et port du serveur
Host = "192.168.56.1"
Port = 6390

# Création du socket
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Liaison du socket à l'adresse et au port spécifiés
socket.bind((Host, Port))

# Attente d'une connexion
socket.listen(1)

# Le script s'arrête jusqu'à une connexion
client, ip = socket.accept()
print("Le client d'ip", ip, "s'est connecté", end='\n\n')

# Génération des clés RSA
key = RSA.generate(2048)
public_key = key.publickey()

print(f"Serveur - Clé publique générée : {public_key.export_key()}", end='\n\n')
client.send(public_key.export_key())

client_public_key = RSA.import_key(client.recv(4096))
print(f"Serveur - Clé publique du client reçue : {client_public_key.export_key()}")

# Création de threads pour l'envoi et la réception simultanés
envoi = Thread(target=Send, args=[client, client_public_key])
recep = Thread(target=Reception, args=[client, key])

# Démarrage des threads
envoi.start()
recep.start()

# Attente de la fin du thread de réception
recep.join()

# Fermeture des connexions
client.close()
socket.close()
