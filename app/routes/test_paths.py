#!/usr/bin/env python3
"""Test path calculations"""
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("Testing path calculations...")
print("="*60)

# Current file location
print(f"Current file: {__file__}")
print(f"Directory of current file: {os.path.dirname(__file__)}")

# Reports directory
reports_dir = os.path.join(os.path.dirname(__file__), '..', 'reports')
print(f"\nReports directory (relative): {reports_dir}")
print(f"Reports directory (absolute): {os.path.abspath(reports_dir)}")

# Check if it exists
if os.path.exists(reports_dir):
    print(f"✓ Reports directory exists")
else:
    print(f"✗ Reports directory does not exist")
    # Create it
    os.makedirs(reports_dir, exist_ok=True)
    print(f"  Created reports directory")

# Test PDF path
report_filename = "test_report.pdf"
full_report_path = os.path.join(reports_dir, report_filename)
print(f"\nFull report path: {full_report_path}")
print(f"Parent directory: {os.path.dirname(full_report_path)}")

# Check if we can write
try:
    with open(full_report_path, 'w') as f:
        f.write("test")
    os.remove(full_report_path)
    print("✓ Can write to reports directory")
except Exception as e:
    print(f"✗ Cannot write to reports directory: {e}")

print("\n" + "="*60)
print("Path test completed")
