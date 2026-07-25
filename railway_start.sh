#!/bin/bash
echo "🚀 Starting VAST Scanner on Railway"
echo "📁 Current directory: $(pwd)"
echo "📁 Files: $(ls -la)"

# Ensure database directory exists
mkdir -p instance

# Set environment variables
export FLASK_ENV=production
export FLASK_DEBUG=0

# Start with gunicorn
exec gunicorn -c gunicorn.conf.py run:app
