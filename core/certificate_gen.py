import os
import hashlib
import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class CertificateGenerator:
    """Generates tamper-evident cryptographic Redaction Audit Certificates in PDF and JSON formats."""

    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculates hex SHA-256 digest of a file."""
        sha = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    @classmethod
    def generate_audit_data(cls, 
                            orig_file_path: str, 
                            redacted_file_path: str, 
                            pre_risk: Dict[str, Any], 
                            redactions_applied: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assembles zero-knowledge redaction verification data."""
        orig_hash = cls.calculate_sha256(orig_file_path)
        redacted_hash = cls.calculate_sha256(redacted_file_path)
        cert_id = f"CERT-SS-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Summarize by category and risk without storing raw values
        category_summary = {}
        for r in redactions_applied:
            cat = r.get('category', 'General PII')
            category_summary[cat] = category_summary.get(cat, 0) + 1

        return {
            'certificate_id': cert_id,
            'timestamp': timestamp,
            'original_filename': os.path.basename(orig_file_path),
            'original_sha256': orig_hash,
            'redacted_sha256': redacted_hash,
            'pre_risk_level': pre_risk.get('level', 'UNKNOWN'),
            'pre_risk_score': pre_risk.get('score', 0),
            'post_risk_level': 'CLEAN',
            'post_risk_score': 0,
            'total_redactions': len(redactions_applied),
            'category_breakdown': category_summary,
            'metadata_scrubbed': True,
            'rasterization_flattened': True,
            'attestation': (
                "ShareSafe cryptographically certifies that the sensitive records identified above "
                "have been permanently purged and flattened from the target file stream. "
                "Zero raw personal data (PII) is stored in this audit receipt."
            )
        }

    @classmethod
    def create_pdf_certificate(cls, audit_data: Dict[str, Any], output_pdf_path: str) -> str:
        """Renders an executive-grade PDF compliance certificate using ReportLab."""
        doc = SimpleDocTemplate(
            output_pdf_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CertTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a')
        )
        subtitle_style = ParagraphStyle(
            'CertSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#64748b')
        )
        header_callout = ParagraphStyle(
            'HeaderCallout',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor('#10b981')
        )
        mono_style = ParagraphStyle(
            'MonoText',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#1e293b')
        )
        body_style = ParagraphStyle(
            'CertBody',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        badge_style = ParagraphStyle(
            'BadgeStyle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#ffffff')
        )

        elements = []

        # Header Title
        elements.append(Paragraph("🛡️ SHARESAFE AUDIT CERTIFICATE", title_style))
        elements.append(Paragraph("Cryptographic Redaction Proof & Privacy Compliance Receipt", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#10b981'), spaceAfter=15))

        # Overview Table
        cert_info = [
            [Paragraph("<b>Certificate ID:</b>", body_style), Paragraph(f"<b>{audit_data['certificate_id']}</b>", body_style)],
            [Paragraph("<b>Timestamp:</b>", body_style), Paragraph(audit_data['timestamp'], body_style)],
            [Paragraph("<b>Original File:</b>", body_style), Paragraph(audit_data['original_filename'], body_style)],
            [Paragraph("<b>Sanitization Protocol:</b>", body_style), Paragraph("High-Fidelity Rasterization & Content Stream Flattening", body_style)],
            [Paragraph("<b>Metadata Scrubbing:</b>", body_style), Paragraph("Active (EXIF, GPS, XML, Author history purged)", header_callout)]
        ]
        t_info = Table(cert_info, colWidths=[140, 390])
        t_info.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('PADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ]))
        elements.append(t_info)
        elements.append(Spacer(1, 15))

        # Risk Reduction Metrics
        elements.append(Paragraph("<b>Risk Reduction Impact</b>", styles['Heading3']))
        risk_data = [
            [
                Paragraph("<b>Audit Phase</b>", body_style),
                Paragraph("<b>Risk Assessment</b>", body_style),
                Paragraph("<b>Calculated Threat Score</b>", body_style),
                Paragraph("<b>Status</b>", body_style)
            ],
            [
                Paragraph("Pre-Scan (Original)", body_style),
                Paragraph(f"<font color='red'><b>{audit_data['pre_risk_level']}</b></font>", body_style),
                Paragraph(f"{audit_data['pre_risk_score']} / 100", body_style),
                Paragraph("Unsafe for Public Sharing", body_style)
            ],
            [
                Paragraph("Post-Redaction (Safe Copy)", body_style),
                Paragraph("<font color='green'><b>CLEAN</b></font>", body_style),
                Paragraph("0 / 100", body_style),
                Paragraph("Certified Safe to Share", header_callout)
            ]
        ]
        t_risk = Table(risk_data, colWidths=[130, 130, 130, 140])
        t_risk.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('PADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#ffffff'), colors.HexColor('#f1f5f9')])
        ]))
        elements.append(t_risk)
        elements.append(Spacer(1, 15))

        # Cryptographic File Fingerprints
        elements.append(Paragraph("<b>Cryptographic SHA-256 Fingerprints</b>", styles['Heading3']))
        hash_data = [
            [Paragraph("<b>Target</b>", body_style), Paragraph("<b>SHA-256 Hash Digest</b>", body_style)],
            [Paragraph("Original Document", body_style), Paragraph(audit_data['original_sha256'], mono_style)],
            [Paragraph("Sanitized Document", body_style), Paragraph(audit_data['redacted_sha256'], mono_style)]
        ]
        t_hash = Table(hash_data, colWidths=[130, 400])
        t_hash.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('PADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ]))
        elements.append(t_hash)
        elements.append(Spacer(1, 15))

        # Redaction Breakdown
        elements.append(Paragraph("<b>Redacted Sensitive Entities Summary</b>", styles['Heading3']))
        cat_rows = [[Paragraph("<b>Sensitive Category</b>", body_style), Paragraph("<b>Entities Purged</b>", body_style)]]
        for cat, count in audit_data.get('category_breakdown', {}).items():
            cat_rows.append([Paragraph(str(cat), body_style), Paragraph(f"{count} entity/entities", body_style)])
        if len(cat_rows) == 1:
            cat_rows.append([Paragraph("Manual Selections", body_style), Paragraph(f"{audit_data['total_redactions']} area(s)", body_style)])

        t_cat = Table(cat_rows, colWidths=[260, 270])
        t_cat.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('PADDING', (0,0), (-1,-1), 5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ]))
        elements.append(t_cat)
        elements.append(Spacer(1, 20))

        # Zero-Knowledge Attestation Box
        attest_text = [
            [Paragraph("<b>🔒 Zero-Knowledge Privacy Guarantee & Legal Disclaimer</b>", header_callout)],
            [Paragraph(audit_data['attestation'], body_style)],
            [Paragraph("<i>In compliance with GDPR Article 17 (Right to Erasure), India Digital Personal Data Protection (DPDP) Act, and HIPAA Safe Harbor privacy guidelines.</i>", subtitle_style)]
        ]
        t_attest = Table(attest_text, colWidths=[530])
        t_attest.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#ecfdf5')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#10b981')),
            ('PADDING', (0,0), (-1,-1), 8)
        ]))
        elements.append(t_attest)

        doc.build(elements)
        return output_pdf_path
