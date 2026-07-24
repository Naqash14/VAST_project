from flask import Blueprint, jsonify

bp = Blueprint('health', __name__)

@bp.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    return jsonify({
        'status': 'healthy',
        'service': 'vast-scanner',
        'version': '1.0.0'
    }), 200
