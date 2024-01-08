from flask import Flask, render_template, session, send_file, abort, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

import binascii

from flask_wtf import FlaskForm
from .forms import LoginForm, RegisterForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend

from io import BytesIO
from PIL import Image

import os
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://example:example@postgres:5432/example'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.secret_key = os.urandom(32)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
#### LOGIN

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    session_key = db.Column(db.LargeBinary, nullable=True)
    image_data = db.Column(db.LargeBinary, nullable=True)
    generation_time = db.Column(db.Float, nullable=True)
    decryption_time = db.Column(db.Float, nullable=True)

    def __init__(self, username, email, password, session_key=None, image_data=None, generation_time=None, decryption_time=None):
        self.username = username
        self.email = email
        self.password = password
        self.session_key = session_key
        self.image_data = image_data
        self.generation_time = generation_time
        self.decryption_time = decryption_time


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
     # Récupérer la clé de session chiffrée de l'utilisateur connecté
    encrypted_session_key = retrieve_encrypted_session_key(current_user.id)

    if encrypted_session_key:
        # Décrypter la clé de session
        decrypted_session_key = decrypt_session_key(encrypted_session_key)

        encrypted_session_key = encrypted_session_key
        decrypted_session_key = decrypted_session_key[0]

        # Afficher dans la console pour des fins de débogage
        print(f"Encrypted Session Key : {encrypted_session_key}")
        print(f"Decrypted Session Key : {decrypted_session_key}")

        # Passer les clés au modèle Jinja pour affichage
        return render_template('index.html', encrypted_session_key=encrypted_session_key, decrypted_session_key=decrypted_session_key)
    else:
        # Gérer le cas où la clé de session n'est pas disponible
        print("Session Key not found for the user.")
        return render_template('index.html', encrypted_session_key=None, decrypted_session_key=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        encrypted_session_key, generation_time = generate_and_encrypt_session_key()
        decrypted_session_key, decryption_time = decrypt_session_key(encrypted_session_key)

        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            session_key=encrypted_session_key,
            generation_time=generation_time,
            decryption_time=decryption_time
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))  # Redirigez vers la page d'accueil ou une autre page après la déconnexion


@app.route('/user_times')
def user_times():
    users = User.query.all()
    
    total_encapsulation_time = 0  # Initialisez la variable ici
    total_decapsulation_time = 0  # Initialisez la variable ici
    p = 0

    for i in range(len(users)):
        total_encapsulation_time += users[i].generation_time
        total_decapsulation_time += users[i].decryption_time
        p += 1

    # Assurez-vous que p n'est pas égal à zéro pour éviter une division par zéro
    if p != 0:
        average_encapsulation_time = total_encapsulation_time / p
        average_decapsulation_time = total_decapsulation_time / p
    else:
        average_encapsulation_time = 0
        average_decapsulation_time = 0

    return render_template('user_times.html', users=users, average_encapsulation_time=average_encapsulation_time, average_decapsulation_time=average_decapsulation_time)


@app.route('/add_users', methods=['POST'])
def add_users():
    # Effacer/Drop la table existante
    db.drop_all()

    # Recréer la table
    db.create_all()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    image_path = os.path.join(script_dir, 'image', 'JUNIA.jpg')

    with open(image_path, 'rb') as image_file:
        binary_data = image_file.read()

    num_users = int(request.form.get('num_users'))
    for i in range(1, num_users + 1):
        username = f'user_{i}'
        encrypted_session_key, generation_time = generate_and_encrypt_session_key()
        decrypted_session_key, decryption_time = decrypt_session_key(encrypted_session_key)
        session_key = encrypted_session_key
        print(f"Encrypted Session Key for user {username}: {session_key}")

        user = User(
            username=username,
            email=f'{username}@example.com',
            password='hashed_password',
            session_key=session_key,
            image_data=binary_data,
            generation_time=generation_time,
            decryption_time=decryption_time
        )

        db.session.add(user)
        db.session.commit()
    return redirect(url_for('user_times'))




#### FIN LOGIN

###RSA
            
def generate_random_session_key():
    return os.urandom(32)

# Chemins vers les fichiers de clés
PRIVATE_KEY_PATH = 'private_key.pem'
PUBLIC_KEY_PATH = 'public_key.pem'
# Génération et stockage de la paire de clés au démarrage de l'application
def generate_and_store_keys():
    # Vérifiez si les clés sont déjà stockées dans des fichiers
    if not (os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH)):
        start_time = time.time()
        # Si elles n'existent pas, générez une nouvelle paire de clés
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Stockez les clés dans des fichiers
        with open(PRIVATE_KEY_PATH, 'wb') as private_key_file:
            private_key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(PUBLIC_KEY_PATH, 'wb') as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        elapsed_time = time.time() - start_time
        print(f"Time taken to generate and store RSA keys: {elapsed_time} seconds")

# Chargez les clés au démarrage de votre application
def load_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Chargez la clé privée
        with open(PRIVATE_KEY_PATH, 'rb') as private_key_file:
            private_key_data = private_key_file.read()
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )
            app.config['private_key'] = private_key

        with open(PUBLIC_KEY_PATH, 'rb') as public_key_file:
            public_key_data = public_key_file.read()
            public_key = serialization.load_pem_public_key(
                public_key_data,
                backend=default_backend()
            )
            app.config['public_key'] = public_key

# Appelez cette fonction lors du démarrage de votre application
generate_and_store_keys()
load_keys()

def generate_and_encrypt_session_key():
    # Récupérez la clé publique depuis le fichier
    start_time = time.time()

    with open(PUBLIC_KEY_PATH, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )

    # Générez et chiffrez la clé de session
    session_key = generate_random_session_key()
    print(f"Session Key (hex): {session_key.hex()}")
    ciphertext = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    elapsed_time = time.time() - start_time
    print(f"Time taken to encrypt session key: {elapsed_time} seconds")
    print(f"Encrypted Session Key (hex): {ciphertext.hex()}")
    return ciphertext, elapsed_time


def retrieve_encrypted_session_key(user_id):
    user = User.query.get(user_id)
    if user:
        return user.session_key
    return None

def decrypt_session_key(encrypted_session_key):
    # Récupérez la clé privée depuis le fichier
    start_time = time.time()

    with open(PRIVATE_KEY_PATH, 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )

    decrypted_session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    elapsed_time = time.time() - start_time
    print(f"Time taken to decrypt session key: {elapsed_time} seconds")
    print(f"Decrypted Session Key: {decrypted_session_key}")

    return decrypted_session_key, elapsed_time



#### FIn RSA

with app.app_context():
    db.create_all()
    print('Creating database...')
    script_dir = os.path.dirname(os.path.abspath(__file__))
    image_path = os.path.join(script_dir, 'image', 'JUNIA.jpg')
    # print(f"Script dir: {script_dir}")
    # print(f"Image path: {image_path}")

    with open(image_path, 'rb') as image_file:
        binary_data = image_file.read()

    # Ajouter l'utilisateur uniquement s'il n'existe pas déjà
    for i in range(1, 21):
        username = f'user_{i}'
        existing_user = User.query.filter_by(username=username).first()
        if not existing_user:
            # Générer et chiffrer la clé de session
            encrypted_session_key, generation_time = generate_and_encrypt_session_key()
            decrypted_session_key, decryption_time = decrypt_session_key(encrypted_session_key)
            session_key = encrypted_session_key
            print(f"Encrypted Session Key for user {username}: {session_key}")

            user = User(
                username=username,
                email=f'{username}@example.com',
                password='hashed_password',
                session_key=session_key,
                image_data=binary_data,
                generation_time=generation_time,
                decryption_time=decryption_time
            )

            db.session.add(user)
            db.session.commit()

    
@app.route('/gallery')
def gallery():
    users_gallery = User.query.all()
    return render_template('gallery.html', user_count=session.get('user_count', 0), users=users_gallery)




@app.route('/get_image/<int:user_id>')
def get_image(user_id):
    user = User.query.get(user_id)
    if user and user.image_data:
        # Ouvrir l'image à partir des données binaires
        image = Image.open(BytesIO(user.image_data))

        # Redimensionner l'image à la taille souhaitée
        resized_image = image.resize((300, 300))  # Remplacez (100, 100) par la taille souhaitée

        # Convertir l'image redimensionnée en données binaires
        buffered = BytesIO()
        resized_image.save(buffered, format="JPEG")
        image_data = buffered.getvalue()

        return send_file(BytesIO(image_data), mimetype='image/jpeg')
    else:
        abort(404)

if __name__ == "__main__":
    app.run(debug=True)



