#!/usr/bin/env python3
import os
import sys
import logging
from app import create_app

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = create_app()

if __name__ == '__main__':
    env = os.environ.get('FLASK_ENV', 'development')
    port = int(os.environ.get('PORT', 5000))
    debug = env == 'development'
    
    logger.info(f"🚀 Starting VAST on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
