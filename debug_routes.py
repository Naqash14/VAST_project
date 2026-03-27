#!/usr/bin/env python3
"""
Debug Blueprint Routes
"""

from app import create_app

app = create_app()

print("=" * 60)
print("🔍 Registered Routes")
print("=" * 60)

with app.app_context():
    for rule in app.url_map.iter_rules():
        print(f"📍 {rule.endpoint:30} → {rule.rule}")
        
        # Specifically check auth routes
        if 'auth' in rule.endpoint:
            print(f"   ✅ Auth route found: {rule.endpoint}")

print("\n" + "=" * 60)

# Check if auth.login exists
try:
    from flask import url_for
    with app.app_context():
        url = url_for('auth.login')
        print(f"✅ auth.login URL: {url}")
except Exception as e:
    print(f"❌ auth.login error: {e}")
