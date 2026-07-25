#!/usr/bin/env python3
"""
VAST Vulnerability Scanner - Main Entry Point
"""

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
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"🚀 Starting VAST Scanner on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
