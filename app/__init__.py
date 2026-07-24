from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
import os
import json
from dotenv import load_dotenv
import logging

load_dotenv()

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    
    # Configuration
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
    app.config['MAIL_ASCII_ATTACHMENTS'] = True
    
    # Session config for Railway
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_COOKIE_NAME'] = 'vast_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # Register JSON filter for templates
    @app.template_filter('json_loads')
    def json_loads_filter(value):
        try:
            return json.loads(value) if value else None
        except:
            return None
    
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Import models and create tables
    with app.app_context():
        try:
            from app import models
            db.create_all()
            logger.info("✅ Database tables created/verified")
            
            # Create admin user if not exists
            from app.models import User
            admin = User.query.filter_by(email=os.environ.get('ADMIN_EMAIL', 'admin@vast.local')).first()
            if not admin:
                admin = User(
                    username=os.environ.get('ADMIN_USERNAME', 'admin'),
                    email=os.environ.get('ADMIN_EMAIL', 'admin@vast.local'),
                    is_admin=True,
                    is_verified=True
                )
                admin.set_password(os.environ.get('ADMIN_PASSWORD', 'Admin@123456'))
                db.session.add(admin)
                db.session.commit()
                logger.info("✅ Admin user created")
        except Exception as e:
            logger.error(f"⚠️ Database error: {e}")
    
    # Register blueprints
    from app.routes import auth, dashboard, projects
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(projects.bp)
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {"status": "healthy", "service": "vast-scanner"}, 200
    
    return app
