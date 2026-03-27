#!/usr/bin/env python3
import os
import sys
import logging
from app import create_app, db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = create_app()

# Auto-create tables on startup
with app.app_context():
    try:
        db.create_all()
        logger.info("✅ Database tables verified/created")
    except Exception as e:
        logger.error(f"❌ Database error: {e}")

if __name__ == '__main__':
    env = os.environ.get('FLASK_ENV', 'development')
    
    if env == 'production':
        host = '0.0.0.0'
        port = int(os.environ.get('PORT', 5000))
        debug = False
        logger.info(f"🚀 Production mode on port {port}")
    else:
        host = '127.0.0.1'
        port = 5000
        debug = True
        logger.info(f"🔧 Development mode on port {port}")
    
    app.run(host=host, port=port, debug=debug)
