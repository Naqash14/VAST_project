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
    
    # FORCE SQLITE on Railway (avoid PostgreSQL issues)
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///vast.db')
    
    # If on Railway, use SQLite
    if 'railway' in os.environ.get('RAILWAY_ENVIRONMENT', ''):
        database_url = 'sqlite:///vast.db'
        print("✅ Railway detected - using SQLite")
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    print(f"✅ Database: {database_url}")
    
    # Email config
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
    
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'app/uploads')
    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    
    # JSON filter
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
    
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    
    # Create upload folder
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Create tables
    with app.app_context():
        try:
            from app import models
            db.create_all()
            print("✅ Database tables created")
            
            # Create admin user
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@vast.local')
            admin_user = models.User.query.filter_by(email=admin_email).first()
            if not admin_user:
                admin = models.User(
                    username=os.environ.get('ADMIN_USERNAME', 'admin'),
                    email=admin_email,
                    is_verified=True,
                    is_admin=True
                )
                admin.set_password(os.environ.get('ADMIN_PASSWORD', 'Admin@123456'))
                db.session.add(admin)
                db.session.commit()
                print("✅ Admin user created")
        except Exception as e:
            print(f"⚠️ Database error: {e}")
    
    # Register blueprints
    from app.routes import auth, dashboard, projects
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(projects.bp)
    
    return app

    # Register health check
    from app.routes import health
    app.register_blueprint(health.bp)
