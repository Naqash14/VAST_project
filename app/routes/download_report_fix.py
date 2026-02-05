import os
from datetime import datetime

def get_report_path(project, scan_id):
    """Generate correct report path"""
    # Create safe project name
    safe_project_name = ''.join(c for c in project.project_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
    report_filename = f"VAST_Report_{safe_project_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    
    # Correct path - from project root
    report_path = os.path.join('app', 'reports', report_filename)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    print(f"Report path: {report_path}")
    print(f"Absolute path: {os.path.abspath(report_path)}")
    
    return report_path

# Test
class MockProject:
    def __init__(self, name):
        self.project_name = name

project = MockProject("Test Project")
path = get_report_path(project, 1)
print(f"Test path: {path}")
