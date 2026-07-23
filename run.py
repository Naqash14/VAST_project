#!/usr/bin/env python3
"""
VAST Vulnerability Scanner - Main Entry Point
"""

import os
import sys
import logging
from app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vast.log')
    ]
)

logger = logging.getLogger(__name__)
app = create_app()

if __name__ == '__main__':
    env = os.environ.get('FLASK_ENV', 'development')
    
    if env == 'production':
        host = '0.0.0.0'
        port = int(os.environ.get('PORT', 5000))
        debug = False
        logger.info(f"🚀 Starting VAST in PRODUCTION mode on port {port}")
    else:
        host = '127.0.0.1'
        port = 5000
        debug = True
        logger.info(f"🔧 Starting VAST in DEVELOPMENT mode on port {port}")
    
    app.run(host=host, port=port, debug=debug)
