from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
import os
import json
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app():
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///vast.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'app/uploads')
    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # Email config
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # Register JSON filter for templates
    @app.template_filter('json_loads')
    def json_loads_filter(value):
        try:
            return json.loads(value) if value else None
        except:
            return None
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    # Set login view - THIS IS CRITICAL
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Create tables
    with app.app_context():
        try:
            from app import models
            db.create_all()
            print("✅ Database tables created/verified")
        except Exception as e:
            print(f"⚠️ Database error: {e}")
    
    # Register blueprints - ORDER MATTERS
    from app.routes import auth, dashboard, projects, admin
    
    app.register_blueprint(auth.bp)      # auth.login must be registered FIRST
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(projects.bp)
    app.register_blueprint(admin.bp)
    
    print("✅ All blueprints registered")
    print(f"📋 Registered endpoints:")
    for rule in app.url_map.iter_rules():
        if 'auth' in rule.endpoint:
            print(f"   - {rule.endpoint} -> {rule.rule}")
    
    return app
