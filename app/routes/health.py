from flask import Blueprint, jsonify
from datetime import datetime

bp = Blueprint('health', __name__)

@bp.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "VAST Vulnerability Scanner",
        "timestamp": datetime.now().isoformat()
    }), 200
