from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://admin:admin@localhost/flask_db'
    app.secret_key = "9rMMpVUskMnXzWBt4zrT8qIy59S"
    db.init_app(app)

    from routes import registrate_routes
    registrate_routes(app, db)
    migrate = Migrate(app, db)

    return app