# Importation des libraries python
import time
import psutil
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import numpy as np
import falcon
from memory_profiler import profile
import random

# ------------

#Execution du progromme classique
def execute_program_normal(n):
    start_time = time.time()
    execution_times_key = []
    execution_times_signature = []
    execution_times_verification = []
    cpu_percentages = []

    message = random.getrandbits(128)
    message = str(message).encode('utf-8')

    for _ in range(10):

    # Generation des cles
        key_generation_start_time = time.time()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=n,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        key_generation_end_time = time.time()
        execution_times_key.append(key_generation_end_time - key_generation_start_time)

    # Signature
        signature_start_time = time.time()
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature_end_time = time.time()
        execution_times_signature.append(signature_end_time - signature_start_time)

        # Verification
        verification_start_time = time.time()
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verification_end_time = time.time()
        execution_times_verification.append(verification_end_time - verification_start_time)

        cpu_percentages.append(psutil.cpu_percent())

    # Affichage du graphique pour la signature
    #plt.figure()
    #plt.scatter(range(1, len(execution_times_signature) + 1), execution_times_signature, marker='.')
    #plt.xlabel('Iteration')
    #plt.ylabel('Temps de signature (s)')
    #plt.title('Temps de signature pour chaque iteration')
    #plt.show()

    # Affichage du graphique pour la verification
    #plt.figure()
    #plt.scatter(range(1, len(execution_times_verification) + 1), execution_times_verification, marker='.')
    #plt.xlabel('Iteration')
    #plt.ylabel('Temps de verification (s)')
    #plt.title('Temps de verification pour chaque iteration')
    #plt.show()

    #Affichage de la taille des clés, du CPU et de differents temps d'execution

    print(f"La taille de la cle est de taille de : {n} bits")
    print(f"Moyenne de l'utilisation CPU : {sum(cpu_percentages) / len(cpu_percentages)} %")
    print(f"Temps moyen de generation des cles : {key_generation_end_time - key_generation_start_time} s")
    print(f"Temps moyen d'execution des signatures : {sum(execution_times_signature)} s")
    print(f"Temps moyen d'execution des verification : {sum(execution_times_verification)} s")
    print(f"Temps d'execution total : {time.time() - start_time} s")


#Execution du progromme quantique
def execute_program_quantum(n):
    start_time = time.time()
    execution_times_key = []
    execution_times_signature = []
    execution_times_verification = []
    cpu_percentages = []

    message = random.getrandbits(128)
    message = str(message).encode('utf-8')

    for _ in range(10):

        # Generation des cles
        key_generation_start_time = time.time()
        sk = falcon.SecretKey(n)
        pk = falcon.PublicKey(sk)
        key_generation_end_time = time.time()
        execution_times_key.append(key_generation_end_time - key_generation_start_time)

        # Signature
        signature_start_time = time.time()
        sig = sk.sign(message)
        signature_end_time = time.time()
        execution_times_signature.append(signature_end_time - signature_start_time)

        # Verification
        verification_start_time = time.time()
        pk.verify(message, sig)
        verification_end_time = time.time()
        execution_times_verification.append(verification_end_time - verification_start_time)

        cpu_percentages.append(psutil.cpu_percent())

    # Affichage du graphique pour la signature
    #plt.figure()
    #plt.scatter(range(1, len(execution_times_signature) + 1), execution_times_signature, marker='.')
    #plt.xlabel('Iteration')
    #plt.ylabel('Temps de signature (s)')
    #plt.title('Temps de signature pour chaque iteration')
    #plt.show()

    # Affichage du graphique pour la verification
    #plt.figure()
    #plt.scatter(range(1, len(execution_times_verification) + 1), execution_times_verification, marker='.')
    #plt.xlabel('Iteration')
    #plt.ylabel('Temps de verification (s)')
    #plt.title('Temps de verification pour chaque iteration')
    #plt.show()

    #Affichage de la taille des clés, du CPU et de differents temps d'execution
    print(f"La taille de la cle est de taille de : {n} bits")
    print(f"Moyenne de l'utilisation CPU : {sum(cpu_percentages) / len(cpu_percentages)} %")
    print(f"Temps moyen de generation des cles : {key_generation_end_time - key_generation_start_time} s")
    print(f"Temps moyen d'execution des signatures : {sum(execution_times_signature)} s")
    print(f"Temps moyen d'execution des verification : {sum(execution_times_verification)} s")
    print(f"Temps d'execution total : {time.time() - start_time} s")

# Demander à l'utilisateur de choisir le programme à exécuter
user_input = input("Entrez 'normal' pour le programme normal et 'quantique' pour le programme quantique: ")

if user_input.lower() == 'normal':
    x = input("Entrez la taille de la cle : ")
    n = int(x)
    execute_program_normal(n)
elif user_input.lower() == 'quantique':
    x = input("Entrez la taille de la cle : ")
    n = int(x)
    execute_program_quantum(n)
else:
    print("Choix non valide.")
