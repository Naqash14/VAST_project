from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os

class PDFReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
    
    def generate_vulnerability_report(self, project_data, scan_results, user_info, findings_details=None, ai_analysis=None):
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1
        )
        story.append(Paragraph("VAST Security Scan Report", title_style))
        story.append(Spacer(1, 10))
        
        # Report metadata
        story.append(Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Project:</b> {project_data.get('project_name', 'Unknown')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Analyzed By:</b> {user_info.get('username', 'Unknown')} ({user_info.get('email', 'Unknown')})", self.styles["Normal"]))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("<b>Executive Summary</b>", self.styles["Heading2"]))
        story.append(Spacer(1, 10))
        
        total_findings = sum(scan_results.values()) if scan_results else 0
        critical = scan_results.get('critical', 0)
        high = scan_results.get('high', 0)
        medium = scan_results.get('medium', 0)
        low = scan_results.get('low', 0)
        
        summary_text = f"Found {total_findings} security issues: {critical} Critical, {high} High, {medium} Medium, {low} Low"
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
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 30))
        
        # Detailed Findings
        if findings_details and len(findings_details) > 0:
            story.append(Paragraph("<b>Detailed Findings</b>", self.styles["Heading2"]))
            story.append(Spacer(1, 10))
            
            for i, finding in enumerate(findings_details, 1):
                severity = finding.get('severity', 'info')
                severity_color = colors.grey
                if severity == 'critical':
                    severity_color = colors.red
                elif severity == 'high':
                    severity_color = colors.orange
                elif severity == 'medium':
                    severity_color = colors.yellow
                elif severity == 'low':
                    severity_color = colors.green
                
                finding_header = f"{i}. [{severity.upper()}] {finding.get('rule_id', finding.get('type', 'Unknown'))}"
                story.append(Paragraph(finding_header, self.styles["Normal"]))
                
                details = [
                    f"<b>Line:</b> {finding.get('line', 'Unknown')} | <b>Tool:</b> {finding.get('tool', 'Unknown')}",
                    f"<b>Message:</b> {finding.get('message', 'No message')}"
                ]
                
                for detail in details:
                    story.append(Paragraph(detail, self.styles["Normal"]))
                
                if finding.get('code_snippet'):
                    story.append(Paragraph(f"<b>Code:</b> {finding.get('code_snippet', '')[:100]}", self.styles["Normal"]))
                
                story.append(Spacer(1, 10))
        
        # AI Analysis Summary - ALL FINDINGS (NO LIMIT)
        if ai_analysis and ai_analysis.get('findings'):
            story.append(Spacer(1, 20))
            story.append(Paragraph("<b>AI-Powered Analysis</b>", self.styles["Heading2"]))
            story.append(Spacer(1, 10))
            
            # Show summary stats
            summary = ai_analysis.get('summary', {})
            if summary:
                story.append(Paragraph(f"<b>AI Summary:</b> {summary.get('critical_count', 0)} Critical, {summary.get('high_count', 0)} High, {summary.get('medium_count', 0)} Medium, {summary.get('low_count', 0)} Low", self.styles["Normal"]))
                story.append(Paragraph(f"<b>Priority:</b> {summary.get('overall_priority', 'N/A')}", self.styles["Normal"]))
                story.append(Spacer(1, 10))
            
            # ALL AI findings - no limit
            for ai_finding in ai_analysis.get('findings', []):
                story.append(Paragraph(f"<b>Finding {ai_finding.get('id', 0) + 1}</b>", self.styles["Normal"]))
                story.append(Paragraph(f"<b>CVSS:</b> {ai_finding.get('cvss_score', 'N/A')} | <b>Priority:</b> {ai_finding.get('priority', 'N/A')}", self.styles["Normal"]))
                story.append(Paragraph(f"<b>Remediation:</b> {ai_finding.get('remediation', 'N/A')}", self.styles["Normal"]))
                story.append(Paragraph(f"<b>Exploitability:</b> {ai_finding.get('exploitability', 'N/A')}", self.styles["Normal"]))
                story.append(Spacer(1, 5))
        
        # Footer
        story.append(Spacer(1, 40))
        footer_text = f"""
        <para alignment='center'>
        <font size=8 color=gray>
        Generated by VAST - Vulnerability Analysis Security Tool<br/>
        Report ID: VAST-{datetime.now().strftime('%Y%m%d%H%M%S')}
        </font>
        </para>
        """
        story.append(Paragraph(footer_text, self.styles["Normal"]))
        
        doc.build(story)
        return self.output_path
