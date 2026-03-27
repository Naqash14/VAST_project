#!/usr/bin/env python3
"""
Debug Session Issues
"""

from flask import session
from app import create_app

app = create_app()

print("=" * 60)
print("🔍 Debugging Session")
print("=" * 60)

with app.app_context():
    # Test session
    session['test'] = 'working'
    print(f"✅ Session set: {session.get('test')}")
    
    # Check session keys
    print(f"📝 Session keys: {list(session.keys())}")
    
    # Try to persist
    session.modified = True
    
    # Read back
    print(f"✅ Session get: {session.get('test')}")

print("\n" + "=" * 60)
