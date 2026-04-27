from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
    
    def generate_vulnerability_report(self, project_data, scan_results, user_info, findings_details=None):
        """Generate professional PDF report"""
        print(f"DEBUG: Generating PDF at: {self.output_path}")
        print(f"DEBUG: Parent directory: {os.path.dirname(self.output_path)}")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        print(f"DEBUG: Directory created/exists")
        
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Header with title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("VAST Vulnerability Scan Report", title_style))
        story.append(Spacer(1, 10))
        
        # Report metadata
        story.append(Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Project Name:</b> {project_data.get('project_name', 'Unknown')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Scan User:</b> {user_info.get('username', 'Unknown')} ({user_info.get('email', 'Unknown')})", self.styles["Normal"]))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("<b>Executive Summary</b>", self.styles["Heading2"]))
        story.append(Spacer(1, 10))
        
        total_findings = sum(scan_results.values()) if scan_results else 0
        if total_findings == 0:
            summary_text = "No security vulnerabilities were found in the scanned code. However, this does not guarantee complete security."
        else:
            critical = scan_results.get('critical', 0)
            high = scan_results.get('high', 0)
            medium = scan_results.get('medium', 0)
            low = scan_results.get('low', 0)
            
            if critical > 0:
                summary_text = f"CRITICAL: {critical} critical vulnerabilities found requiring immediate attention."
            elif high > 0:
                summary_text = f"HIGH: {high} high severity vulnerabilities found requiring prompt remediation."
            elif medium > 0:
                summary_text = f"MEDIUM: {medium} medium severity vulnerabilities found that should be addressed."
            else:
                summary_text = f"LOW: {low} low severity findings identified for review."
        
        story.append(Paragraph(summary_text, self.styles["Normal"]))
        story.append(Spacer(1, 20))
        
        # Statistics Table
        story.append(Paragraph("<b>Vulnerability Statistics</b>", self.styles["Heading2"]))
        
        stats_data = [
            ['Severity Level', 'Count', 'Risk Level'],
            ['Critical', scan_results.get('critical', 0), 'Extreme'],
            ['High', scan_results.get('high', 0), 'High'],
            ['Medium', scan_results.get('medium', 0), 'Medium'],
            ['Low', scan_results.get('low', 0), 'Low'],
            ['Informational', scan_results.get('info', 0), 'Info'],
            ['Total', total_findings, '-']
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a6fa5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 30))
        
        # Detailed Findings
        if findings_details and len(findings_details) > 0:
            story.append(Paragraph("<b>Detailed Findings</b>", self.styles["Heading2"]))
            story.append(Spacer(1, 10))
            
            for i, finding in enumerate(findings_details[:20], 1):  # Limit to first 20 findings
                # Severity color text
                severity = finding.get('severity', 'info').upper()
                
                # Finding header
                finding_header = f"{i}. [{severity}] {finding.get('rule_id', 'Pattern Match')}"
                story.append(Paragraph(finding_header, self.styles["Normal"]))
                
                # Finding details
                details = [
                    f"<b>Location:</b> Line {finding.get('line', 'Unknown')}",
                    f"<b>Message:</b> {finding.get('message', 'No message')}",
                    f"<b>Type:</b> {finding.get('type', 'other').replace('_', ' ').title()}"
                ]
                
                for detail in details:
                    story.append(Paragraph(detail, self.styles["Normal"]))
                
                story.append(Spacer(1, 10))
        
        # Recommendations
        story.append(Spacer(1, 20))
        story.append(Paragraph("<b>Security Recommendations</b>", self.styles["Heading2"]))
        
        recommendations = [
            "1. Always validate and sanitize user inputs before processing",
            "2. Use parameterized queries or prepared statements for database operations",
            "3. Implement proper authentication and authorization mechanisms",
            "4. Keep all dependencies and libraries updated to latest secure versions",
            "5. Encrypt sensitive data both in transit and at rest",
            "6. Implement proper error handling without revealing system details",
            "7. Conduct regular security testing and code reviews",
            "8. Follow the principle of least privilege for all system components",
            "9. Implement logging and monitoring for security events",
            "10. Use secure coding practices and frameworks"
        ]
        
        for rec in recommendations:
            story.append(Paragraph(rec, self.styles["Normal"]))
        
        # Footer
        story.append(Spacer(1, 40))
        footer_text = """
        <para alignment='center'>
        <font size=8 color=gray>
        Generated by VAST Vulnerability Scanner<br/>
        Automated Security Analysis Tool<br/>
        Report ID: {report_id}<br/>
        For security inquiries, contact your security team
        </font>
        </para>
        """.format(report_id=datetime.now().strftime('%Y%m%d%H%M%S'))
        
        story.append(Paragraph(footer_text, self.styles["Normal"]))
        
        # Build PDF
        try:
            doc.build(story)
            print(f"DEBUG: PDF generated successfully: {self.output_path}")
            print(f"DEBUG: File exists: {os.path.exists(self.output_path)}")
            print(f"DEBUG: File size: {os.path.getsize(self.output_path) if os.path.exists(self.output_path) else 'N/A'} bytes")
            return self.output_path
        except Exception as e:
            print(f"DEBUG: Error building PDF: {str(e)}")
            raise
