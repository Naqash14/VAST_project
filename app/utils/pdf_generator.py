"""
PDF Report Generator - Professional VAST Report
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        """Create custom styles for professional report"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1e293b'),
            alignment=TA_CENTER,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#3b82f6'),
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubheading',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#475569'),
            spaceBefore=10,
            spaceAfter=5,
            fontName='Helvetica-Bold'
        ))
        
        # Normal text style
        self.styles.add(ParagraphStyle(
            name='CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#334155'),
            leading=14
        ))
        
        # Footer style
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#94a3b8'),
            alignment=TA_CENTER
        ))
    
    def generate_vulnerability_report(self, project_data, scan_results, user_info, findings_details=None):
        """Generate professional PDF vulnerability report"""
        
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
            title=f"VAST_Report_{project_data.get('project_name', 'Scan')}"
        )
        
        story = []
        
        # ===== HEADER SECTION =====
        story.append(Spacer(1, 20))
        
        # Logo and Title
        logo_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'images', 'vast_logo.png')
        if os.path.exists(logo_path):
            try:
                logo = Image(logo_path, width=1.2*inch, height=1.2*inch)
                logo.hAlign = 'CENTER'
                story.append(logo)
                story.append(Spacer(1, 10))
            except:
                pass
        
        story.append(Paragraph("VAST Security Scanner", self.styles['CustomTitle']))
        story.append(Paragraph("Vulnerability Assessment Report", self.styles['CustomNormal']))
        story.append(Spacer(1, 20))
        
        # Report Metadata
        meta_data = [
            ['Report ID:', f"VAST-{datetime.now().strftime('%Y%m%d%H%M%S')}"],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Project:', project_data.get('project_name', 'Unknown')],
            ['User:', user_info.get('username', 'Unknown')],
            ['Email:', user_info.get('email', 'Unknown')],
        ]
        
        meta_table = Table(meta_data, colWidths=[1.5*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#64748b')),
            ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e293b')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 20))
        
        # ===== EXECUTIVE SUMMARY =====
        story.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        
        total_findings = sum(scan_results.values()) if scan_results else 0
        
        if total_findings == 0:
            summary = "No security vulnerabilities were detected in the scanned code. However, this does not guarantee complete security. We recommend regular security testing and code reviews."
        else:
            critical = scan_results.get('critical', 0)
            high = scan_results.get('high', 0)
            medium = scan_results.get('medium', 0)
            low = scan_results.get('low', 0)
            
            summary = f"This report identifies {total_findings} security issues across different severity levels. "
            if critical > 0:
                summary += f"<b>{critical} CRITICAL</b> issues require immediate attention. "
            if high > 0:
                summary += f"<b>{high} HIGH</b> severity issues should be addressed promptly. "
            if medium > 0:
                summary += f"<b>{medium} MEDIUM</b> priority issues should be reviewed. "
            if low > 0:
                summary += f"<b>{low} LOW</b> severity issues are found."
        
        story.append(Paragraph(summary, self.styles['CustomNormal']))
        story.append(Spacer(1, 20))
        
        # ===== VULNERABILITY STATISTICS =====
        story.append(Paragraph("Vulnerability Statistics", self.styles['CustomHeading']))
        
        # Simple stats table - NO Risk Level or Action Required columns
        stats_data = [
            ['Severity', 'Count'],
            ['Critical', str(scan_results.get('critical', 0))],
            ['High', str(scan_results.get('high', 0))],
            ['Medium', str(scan_results.get('medium', 0))],
            ['Low', str(scan_results.get('low', 0))],
         
            ['Total', str(total_findings)]
        ]
        
        stats_table = Table(stats_data, colWidths=[2.5*inch, 1.5*inch])
        
        # Color rows based on severity
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#fef2f2')),  # Critical row
            ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#dc2626')),
            ('BACKGROUND', (0, 2), (0, 2), colors.HexColor('#fffbeb')),  # High row
            ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#d97706')),
            ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#eff6ff')),  # Medium row
            ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#2563eb')),
            ('BACKGROUND', (0, 4), (0, 4), colors.HexColor('#f8fafc')),  # Low row
            ('TEXTCOLOR', (0, 4), (0, 4), colors.HexColor('#64748b')),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 20))
        
        # ===== DETAILED FINDINGS =====
        if findings_details and len(findings_details) > 0:
            story.append(Paragraph("Detailed Findings", self.styles['CustomHeading']))
            
            # Group findings by severity
            findings_by_severity = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            }
            
            for finding in findings_details:
                severity = finding.get('severity', 'info').lower()
                if severity in findings_by_severity:
                    findings_by_severity[severity].append(finding)
            
            # Display findings by severity order
            for severity, color, icon in [
                ('critical', '#dc2626', '🔴'),
                ('high', '#d97706', '🟠'),
                ('medium', '#2563eb', '🔵'),
                ('low', '#64748b', '🟢'),
                ('info', '#94a3b8', 'ℹ️')
            ]:
                findings = findings_by_severity.get(severity, [])
                if findings:
                    story.append(Paragraph(f"{icon} {severity.upper()} Severity ({len(findings)} issues)", 
                                          self.styles['CustomSubheading']))
                    
                    for i, finding in enumerate(findings[:10], 1):  # Limit to 10 per severity
                        # Finding header
                        finding_text = f"<b>{i}. {finding.get('message', 'No message')[:150]}</b>"
                        story.append(Paragraph(finding_text, self.styles['CustomNormal']))
                        
                        # Details
                        details = []
                        if finding.get('line'):
                            details.append(f"📍 Line: {finding.get('line')}")
                        if finding.get('tool'):
                            details.append(f"🔧 Tool: {finding.get('tool')}")
                        if finding.get('analysis_type'):
                            details.append(f"📊 Analysis: {finding.get('analysis_type')}")
                        
                        if details:
                            story.append(Paragraph(" | ".join(details), self.styles['CustomNormal']))
                        
                        # Remediation
                        if finding.get('remediation'):
                            remediation_text = f"<font color='#10b981'>💡 Fix:</font> {finding.get('remediation')}"
                            story.append(Paragraph(remediation_text, self.styles['CustomNormal']))
                        
                        story.append(Spacer(1, 8))
                    
                    if len(findings) > 10:
                        story.append(Paragraph(f"... and {len(findings) - 10} more {severity} severity findings", 
                                              self.styles['CustomNormal']))
                    story.append(Spacer(1, 10))
        
        # ===== SECURITY RECOMMENDATIONS =====
        story.append(PageBreak())
        story.append(Paragraph("Security Recommendations", self.styles['CustomHeading']))
        
        recommendations = [
            "1. <b>Input Validation:</b> Always validate and sanitize all user inputs before processing",
            "2. <b>Parameterized Queries:</b> Use prepared statements for database operations to prevent SQL injection",
            "3. <b>Memory Safety:</b> Implement proper bounds checking and use safe functions (strncpy vs strcpy)",
            "4. <b>Error Handling:</b> Avoid exposing sensitive information in error messages",
            "5. <b>Secure Authentication:</b> Implement strong password policies and multi-factor authentication",
            "6. <b>Regular Updates:</b> Keep all dependencies and libraries updated to latest secure versions",
            "7. <b>Least Privilege:</b> Run applications with minimum required privileges",
            "8. <b>Logging & Monitoring:</b> Implement comprehensive logging for security events",
            "9. <b>Code Review:</b> Conduct regular security code reviews and testing",
            "10. <b>Secure Configuration:</b> Disable debug mode and unnecessary features in production"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles['CustomNormal']))
            story.append(Spacer(1, 6))
        
        # ===== FOOTER =====
        story.append(Spacer(1, 40))
        footer_text = f"""
        <font size=8 color=#94a3b8>
        ────────────────────────────────────────────────────────────────────────────────<br/>
        VAST Security Scanner | Professional Vulnerability Assessment Tool<br/>
        Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        This report is for authorized security testing purposes only.
        </font>
        """
        story.append(Paragraph(footer_text, self.styles['Footer']))
        
        # Build PDF
        doc.build(story)
        print(f"✅ PDF Report generated: {self.output_path}")
        return self.output_path
