"""
PDF Report Generator - VAST Scanner
Generates professional vulnerability reports with AI analysis
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os
import json

class PDFReportGenerator:
    def __init__(self, output_path):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Add custom styles"""
        self.styles.add(ParagraphStyle(
            name='Title',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,
            textColor=colors.HexColor('#1a365d')
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#2d3748')
        ))
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=6,
            textColor=colors.HexColor('#1a202c')
        ))
        self.styles.add(ParagraphStyle(
            name='AITitle',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.HexColor('#2b6cb0')
        ))
        self.styles.add(ParagraphStyle(
            name='AIText',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=4,
            textColor=colors.HexColor('#2d3748')
        ))

    def generate_vulnerability_report(self, project_data, scan_results, user_info, findings_details=None, ai_analysis=None):
        """Generate professional PDF report with AI analysis"""
        doc = SimpleDocTemplate(
            self.output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        story = []
        
        # ===== HEADER =====
        story.append(Paragraph("VAST Security Scan Report", self.styles['Title']))
        story.append(Spacer(1, 10))
        
        # Report metadata
        story.append(Paragraph(f"<b>Report Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Project:</b> {project_data.get('project_name', 'Unknown')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Analyzed By:</b> {user_info.get('username', 'Unknown')} ({user_info.get('email', 'Unknown')})", self.styles["Normal"]))
        story.append(Spacer(1, 20))
        
        # ===== EXECUTIVE SUMMARY =====
        story.append(Paragraph("<b>Executive Summary</b>", self.styles["SectionTitle"]))
        
        total = sum(scan_results.values()) if scan_results else 0
        critical = scan_results.get('critical', 0)
        high = scan_results.get('high', 0)
        medium = scan_results.get('medium', 0)
        low = scan_results.get('low', 0)
        
        summary_text = f"Found {total} security issues: {critical} Critical, {high} High, {medium} Medium, {low} Low"
        story.append(Paragraph(summary_text, self.styles["Normal"]))
        story.append(Spacer(1, 20))
        
        # ===== STATISTICS TABLE =====
        story.append(Paragraph("<b>Vulnerability Statistics</b>", self.styles["SectionTitle"]))
        
        stats_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['Critical', critical, 'Extreme'],
            ['High', high, 'High'],
            ['Medium', medium, 'Medium'],
            ['Low', low, 'Low'],
            ['Total', total, '-']
        ]
        
        stats_table = Table(stats_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a6fa5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 30))
        
        # ===== FINDINGS =====
        story.append(Paragraph("<b>All Detected Vulnerabilities</b>", self.styles["SectionTitle"]))
        
        if findings_details:
            for i, finding in enumerate(findings_details[:20], 1):
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
                
                finding_text = f"{i}. [{severity.upper()}] {finding.get('message', 'No message')}"
                story.append(Paragraph(finding_text, self.styles["FindingTitle"]))
                story.append(Paragraph(f"<b>Line:</b> {finding.get('line', 'Unknown')} | <b>Tool:</b> {finding.get('tool', 'Unknown')}", self.styles["Normal"]))
                if finding.get('code_snippet'):
                    story.append(Paragraph(f"<b>Code:</b> {finding.get('code_snippet', '')[:80]}...", self.styles["Normal"]))
                story.append(Spacer(1, 8))
        
        # ===== AI ANALYSIS SECTION =====
        if ai_analysis:
            story.append(PageBreak())
            story.append(Paragraph("<b>AI-Powered Analysis</b>", self.styles["SectionTitle"]))
            story.append(Paragraph("Expert recommendations generated by AI security assistant", self.styles["Normal"]))
            story.append(Spacer(1, 10))
            
            # AI Summary
            ai_data = ai_analysis if isinstance(ai_analysis, dict) else json.loads(ai_analysis)
            
            if 'summary' in ai_data:
                summary = ai_data['summary']
                ai_summary_text = f"Critical: {summary.get('critical_count', 0)} | High: {summary.get('high_count', 0)} | Medium: {summary.get('medium_count', 0)} | Low: {summary.get('low_count', 0)}"
                story.append(Paragraph(f"<b>AI Summary:</b> {ai_summary_text}", self.styles["Normal"]))
                story.append(Paragraph(f"<b>Priority:</b> {summary.get('overall_priority', 'Review findings.')}", self.styles["Normal"]))
                story.append(Spacer(1, 10))
            
            if 'findings' in ai_data:
                for ai_finding in ai_data['findings'][:15]:
                    story.append(Paragraph(f"<b>Finding #{ai_finding.get('id', 0) + 1}</b>", self.styles["AITitle"]))
                    story.append(Paragraph(f"<b>CVSS:</b> {ai_finding.get('cvss_score', 'N/A')} | <b>Priority:</b> {ai_finding.get('priority', 'N/A')}", self.styles["AIText"]))
                    story.append(Paragraph(f"<b>Remediation:</b> {ai_finding.get('remediation', 'N/A')}", self.styles["AIText"]))
                    story.append(Paragraph(f"<b>Exploitability:</b> {ai_finding.get('exploitability', 'N/A')}", self.styles["AIText"]))
                    story.append(Spacer(1, 8))
        
        # ===== FOOTER =====
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"<i>Generated by VAST - Vulnerability Analysis Security Tool</i>",
            self.styles["Normal"]
        ))
        story.append(Paragraph(
            f"<font size=8 color=gray>Report ID: VAST-{datetime.now().strftime('%Y%m%d%H%M%S')}</font>",
            self.styles["Normal"]
        ))
        
        # Build PDF
        doc.build(story)
        return self.output_path
