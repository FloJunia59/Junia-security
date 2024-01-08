import time
from app import db, app

time.sleep(15)

with app.app_context():
    db.create_all()