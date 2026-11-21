import re
from typing import List, Dict, Any, Optional

class PrivacyAssistant:
    """Intelligent Privacy Assistant for ShareSafe.
    Analyzes document detection results to provide context-aware, explainable privacy
    guidance and actionable redaction recommendations.
    
    Operates locally and deterministically without external API dependencies.
    """

    PRIORITY_LEVELS = {
        'HIGH_PRIORITY': {
            'label': 'High Priority',
            'css_class': 'priority-high',
            'icon': 'fa-solid fa-triangle-exclamation',
            'order': 1
        },
        'REVIEW': {
            'label': 'Review Recommended',
            'css_class': 'priority-review',
            'icon': 'fa-solid fa-circle-question',
            'order': 2
        },
        'INFORMATIONAL': {
            'label': 'Informational',
            'css_class': 'priority-info',
            'icon': 'fa-solid fa-circle-info',
            'order': 3
        }
    }

    @classmethod
    def generate_recommendations(cls, 
                                 detections: List[Dict[str, Any]], 
                                 sharing_context: str = 'academic',
                                 file_name: str = 'Document',
                                 is_pdf: bool = False,
                                 page_count: int = 1) -> Dict[str, Any]:
        """Generates structured, context-aware privacy recommendations and an explainable summary."""
        context = (sharing_context or 'academic').lower()
        if context not in ('academic', 'professional', 'private', 'public'):
            context = 'academic'

        recommendations = []
        confirmed_count = 0
        uncertain_count = 0
        type_counts = {}

        for d in detections:
            rec = cls._evaluate_detection(d, context)
            if rec:
                recommendations.append(rec)
                t = d.get('type', 'general')
                type_counts[t] = type_counts.get(t, 0) + 1
                if rec.get('review_required') or rec.get('confidence') == 'low':
                    uncertain_count += 1
                else:
                    confirmed_count += 1

        # Sort recommendations: High Priority first, then Review, then Informational
        recommendations.sort(key=lambda r: (cls.PRIORITY_LEVELS[r['priority']]['order'], r.get('page', 1)))

        # Compile statistics
        stats = {
            'total': len(recommendations),
            'pending': len(recommendations),
            'accepted': 0,
            'dismissed': 0,
            'confirmed': confirmed_count,
            'uncertain': uncertain_count,
            'high_priority': sum(1 for r in recommendations if r['priority'] == 'HIGH_PRIORITY'),
            'review_recommended': sum(1 for r in recommendations if r['priority'] == 'REVIEW'),
            'informational': sum(1 for r in recommendations if r['priority'] == 'INFORMATIONAL')
        }

        # Generate explainable narrative summary
        summary = cls._generate_summary(detections, recommendations, stats, context, file_name)

        return {
            'summary': summary,
            'recommendations': recommendations,
            'stats': stats,
            'context': context,
            'file_name': file_name
        }

    @classmethod
    def _evaluate_detection(cls, detection: Dict[str, Any], context: str) -> Optional[Dict[str, Any]]:
        """Evaluates a single detected entity and produces contextual guidance."""
        d_type = detection.get('type', 'unknown')
        d_label = detection.get('label', 'Sensitive Item')
        d_val = detection.get('value', '')
        d_masked = detection.get('masked', d_val)
        d_risk = detection.get('risk', 'LOW').upper()
        d_cat = detection.get('category', 'General Information')
        d_page = detection.get('page', 1)
        d_bbox = detection.get('bbox')
        det_id = detection.get('id', '')
        review_required = detection.get('review_required', False)
        confidence = detection.get('confidence', 'high')
        payload_type = detection.get('payload_type')

        # Baseline decision variables
        priority = 'INFORMATIONAL'
        action = 'LEAVE'
        action_label = 'Keep Unredacted'
        suggested_style = 'blackout'
        explanation = ''
        risk_description = ''
        recommendation = ''

        # 1. Government Identifiers (Aadhaar, SSN, Passport, PAN, DL, Voter ID, NINO, SIN)
        if d_type in ('aadhaar', 'ssn', 'passport', 'pan', 'driving_licence', 'voter_id', 'nino', 'sin'):
            if review_required or confidence == 'low':
                priority = 'REVIEW'
                action = 'REVIEW'
                action_label = 'Verify & Decide'
                explanation = f"Matches the formatting of an official identity record ({d_label}), but checksum or contextual markers are unconfirmed."
                risk_description = "Could be an ordinary internal document number, invoice code, or OCR transcription variance."
                recommendation = "Inspect the highlighted document text. Apply redaction only if you confirm this is a genuine personal identifier."
            else:
                priority = 'HIGH_PRIORITY'
                action = 'REDACT'
                action_label = 'Redact Record'
                explanation = f"Exposes an official government-issued personal identity identifier ({d_label})."
                risk_description = "High statutory privacy risk. Exposure can lead to identity theft, account takeover, or regulatory compliance violations."
                recommendation = "Redact this finding before sharing. Government identification numbers are rarely required by external parties."

        # 2. Generic or Unclassified Identifiers
        elif d_type == 'identifier_candidate':
            priority = 'REVIEW'
            action = 'REVIEW'
            action_label = 'Inspect Region'
            explanation = "A structured numeric sequence resembling an identifier, but lacks specific government registry confirmation."
            risk_description = "May represent a harmless part number, software serial, or internal reference code rather than personal data."
            recommendation = "Review whether this number is intended to be confidential. Leave unchanged if it is non-sensitive operational data."

        # 3. Credit Cards & Payment VPAs
        elif d_type in ('credit_card', 'upi_vpa'):
            if review_required or d_label == 'Payment Card Candidate':
                priority = 'REVIEW'
                action = 'REVIEW'
                action_label = 'Verify Card'
                explanation = "A 16-digit numeric grouping formatted like a payment card, but lacking confirmed bank network verification."
                risk_description = "May be an order tracking code or hardware ID rather than active financial credentials."
                recommendation = "Check if this represents an active credit/debit card. Redact immediately if payment data is present."
            else:
                priority = 'HIGH_PRIORITY'
                action = 'REDACT'
                action_label = 'Redact Financial Data'
                explanation = f"Direct financial payment instrument ({d_label})."
                risk_description = "Direct financial exposure. Third parties could attempt fraudulent transactions or extract cardholder identity."
                recommendation = "Always redact financial payment identifiers using solid blackout before document distribution."

        # 4. API Keys, JWT Tokens, and Cloud Credentials
        elif d_type in ('api_key', 'token'):
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Credential'
            explanation = f"Developer or service authentication secret ({d_label})."
            risk_description = "Severe infrastructure risk. Allows unauthorized access to servers, databases, or cloud accounts."
            recommendation = "Permanently redact this token. If this document was already shared externally, revoke and rotate the secret immediately."

        # 5. Telephone / Phone Numbers
        elif d_type == 'phone':
            if context in ('public', 'professional'):
                priority = 'HIGH_PRIORITY'
                action = 'REDACT'
                action_label = 'Redact Phone'
                suggested_style = 'blackout'
                explanation = "Direct telephone contact line associated with an individual or organization."
                risk_description = f"In {context.capitalize()} mode, exposed telephone numbers risk unsolicited calls, SMS phishing, or social engineering."
                recommendation = "Redact unless this telephone number is explicitly published as a public customer service line."
            else:
                priority = 'REVIEW'
                action = 'REVIEW'
                action_label = 'Review Phone'
                suggested_style = 'blur'
                explanation = "Direct telephone contact number."
                risk_description = "Allows anyone with access to the document to contact or lookup the associated individual."
                recommendation = "Review whether recipients need this contact information. Redact or blur if sharing with untrusted peers."

        # 6. Email Addresses
        elif d_type == 'email':
            if context == 'public':
                priority = 'HIGH_PRIORITY'
                action = 'REDACT'
                action_label = 'Redact Email'
                explanation = "Personal or corporate electronic mail address."
                risk_description = "Public exposure invites spam harvesting, credential stuffing attempts, and targeted phishing."
                recommendation = "Redact email addresses before distributing documents to public web channels."
            else:
                priority = 'REVIEW'
                action = 'REVIEW'
                action_label = 'Review Email'
                suggested_style = 'blur'
                explanation = "Personal or corporate electronic mail address."
                risk_description = "Reveals the identity and communication channel of the individual."
                recommendation = "Review if the recipient requires this email. Safe to leave unredacted for trusted peer collaboration."

        # 7. IPv4 Addresses
        elif d_type == 'ip_address':
            priority = 'REVIEW'
            action = 'REVIEW'
            action_label = 'Review IP'
            suggested_style = 'pixelate'
            explanation = "Network host or gateway internet protocol address."
            risk_description = "Exposes internal network addressing or server locations to external reconnaissance."
            recommendation = "Review if network topology should be kept confidential. Redact or pixelate for public tutorials and coursework."

        # 8. Date of Birth (DOB)
        elif d_type == 'dob':
            priority = 'REVIEW'
            action = 'REDACT'
            action_label = 'Redact DOB'
            suggested_style = 'blackout'
            explanation = "Official demographic date of birth record."
            risk_description = "Often used as a verification factor for identity verification and account recovery."
            recommendation = "Redact the birth date to minimize demographic profile disclosure."

        # 8.1 Personal / Patient Names
        elif d_type == 'name':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Name'
            suggested_style = 'blackout'
            explanation = f"Personal name identifying an individual ({d_label})."
            risk_description = "Directly identifies the patient, customer, resident, or individual associated with this record."
            recommendation = "Redact patient and personal names before document distribution to preserve confidentiality."

        # 8.2 Billing and Residential Addresses
        elif d_type == 'address':
            priority = 'HIGH_PRIORITY' if context in ('public', 'professional') else 'REVIEW'
            action = 'REDACT'
            action_label = 'Redact Address'
            suggested_style = 'blackout'
            explanation = f"Physical location or mailing record ({d_label})."
            risk_description = "Exposes personal residential address or billing location."
            recommendation = "Redact address information to prevent physical location tracking and preserve home privacy."

        # 8.3 Card Expiration Date
        elif d_type == 'expiration_date':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Expiration'
            suggested_style = 'blackout'
            explanation = "Payment card expiration date credential."
            risk_description = "Used alongside payment card numbers to authorize financial transactions."
            recommendation = "Always redact payment expiration dates alongside payment card numbers."

        # 8.4 Bank Account Numbers
        elif d_type == 'bank_account':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Bank Account'
            suggested_style = 'blackout'
            explanation = "Direct financial institution banking account number."
            risk_description = "Exposes personal or corporate banking details, inviting fraud or unauthorized debits."
            recommendation = "Redact bank account numbers before sharing documents externally."

        # 8.5 International Bank Account Numbers (IBAN)
        elif d_type == 'iban':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact IBAN'
            suggested_style = 'blackout'
            explanation = "International Bank Account Number (IBAN) with verified country routing."
            risk_description = "Global financial identifier linking directly to an active bank account."
            recommendation = "Always redact international bank account numbers to prevent payment diversion or fraud."

        # 8.6 Bank Clearing / Routing Identifiers (ABA / IFSC)
        elif d_type in ('bank_routing', 'bank_ifsc'):
            priority = 'HIGH_PRIORITY' if context in ('public', 'professional') else 'REVIEW'
            action = 'REDACT'
            action_label = 'Redact Routing Code'
            suggested_style = 'blackout'
            explanation = f"Financial institution routing code ({d_label})."
            risk_description = "Identifies specific banking institutions, clearing houses, and branch locations."
            recommendation = "Redact routing transit numbers when accompanied by account numbers."

        # 8.7 Card Security Code (CVV / CVC)
        elif d_type == 'cvv_code':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact CVV'
            suggested_style = 'blackout'
            explanation = "Card Verification Value (CVV/CVC) payment authentication secret."
            risk_description = "Critical financial secret enabling card-not-present unauthorized transactions."
            recommendation = "Must be permanently redacted before any document sharing."

        # 8.8 SWIFT / BIC Code
        elif d_type == 'swift_bic':
            priority = 'REVIEW'
            action = 'REVIEW'
            action_label = 'Review SWIFT Code'
            suggested_style = 'blackout'
            explanation = "SWIFT Business Identifier Code for international interbank transfers."
            risk_description = "Identifies corporate or institutional banking partners."
            recommendation = "Review if institutional banking relationships should remain private."

        # 8.9 Tax Identification / Payment Transaction Ref
        elif d_type in ('tax_ein', 'payment_txn'):
            priority = 'REVIEW'
            action = 'REVIEW'
            action_label = 'Review Financial Ref'
            suggested_style = 'blackout'
            explanation = f"Financial reference identifier ({d_label})."
            risk_description = "May disclose tax registration or specific payment audit trails."
            recommendation = "Review whether this financial transaction or tax identifier should be redacted."

        # 8.10 Employee Identifiers
        elif d_type == 'employee_id':
            priority = 'HIGH_PRIORITY' if context in ('public', 'professional') else 'REVIEW'
            action = 'REDACT' if context == 'public' else 'REVIEW'
            action_label = 'Redact Employee ID' if context == 'public' else 'Review Employee ID'
            suggested_style = 'blackout'
            explanation = "Corporate employee badge or staff identification code."
            risk_description = "Can be leveraged for social engineering, spear-phishing, or employee impersonation."
            recommendation = "Redact internal employee IDs before distributing files to external or public recipients."

        # 8.11 Confidential Business Information & Markings
        elif d_type == 'confidential_marking':
            priority = 'HIGH_PRIORITY'
            action = 'REVIEW'
            action_label = 'Review Confidential Banner'
            suggested_style = 'blackout'
            explanation = f"Protective marking or confidentiality banner ({d_label})."
            risk_description = "Explicitly indicates that the document contains non-public proprietary or restricted content."
            recommendation = "Verify if this confidential document is authorized for disclosure before sharing."

        # 8.12 Internal Reference Numbers
        elif d_type == 'internal_reference':
            priority = 'REVIEW'
            action = 'REVIEW'
            action_label = 'Review Reference #'
            suggested_style = 'blackout'
            explanation = f"Internal organizational reference code ({d_label})."
            risk_description = "May expose internal project designations, purchase orders, or contract codes."
            recommendation = "Review whether this reference number is sensitive or safe to leave unredacted."

        # 8.13 Patient Identifiers
        elif d_type == 'patient_id':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Patient ID'
            suggested_style = 'blackout'
            explanation = "Direct patient identification code."
            risk_description = "Exposes Protected Health Information (PHI) subject to healthcare confidentiality and HIPAA privacy rules."
            recommendation = "Always redact patient identifiers before document transmission or sharing."

        # 8.14 Medical Record Numbers (MRN)
        elif d_type == 'mrn':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Medical Record #'
            suggested_style = 'blackout'
            explanation = "Medical Record Number (MRN) or clinical chart number."
            risk_description = "Directly indexes patient medical history and confidential diagnostic records."
            recommendation = "Permanently redact medical record numbers to prevent unauthorized access to clinical history."

        # 8.15 Health Insurance Identifiers
        elif d_type == 'health_insurance':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Health Insurance'
            suggested_style = 'blackout'
            explanation = "Healthcare insurance member ID, group policy, or Medicaid/Medicare number."
            risk_description = "Can lead to medical identity fraud, fraudulent claims, or privacy violation."
            recommendation = "Redact health insurance member and policy numbers before document distribution."

        # 8.16 Prescription Rx Numbers
        elif d_type == 'prescription_rx':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Prescription Rx'
            suggested_style = 'blackout'
            explanation = "Pharmacy prescription order (Rx) number."
            risk_description = "Discloses confidential prescription details and pharmacy dispensing records."
            recommendation = "Redact prescription numbers to protect medication privacy."

        # 8.17 Medical Condition / Diagnosis
        elif d_type == 'medical_condition':
            priority = 'HIGH_PRIORITY'
            action = 'REDACT'
            action_label = 'Redact Medical Condition'
            suggested_style = 'blackout'
            explanation = f"Medical diagnosis or clinical finding ({d_label})."
            risk_description = "Discloses personal healthcare diagnoses and medical conditions."
            recommendation = "Redact sensitive medical findings and diagnoses to protect patient health privacy."

        # 8.18 Attending Physician / Doctor
        elif d_type == 'attending_physician':
            priority = 'HIGH_PRIORITY' if context in ('public', 'professional') else 'REVIEW'
            action = 'REDACT'
            action_label = 'Redact Physician'
            suggested_style = 'blackout'
            explanation = "Attending physician or healthcare provider name."
            risk_description = "Associates healthcare provider identities with clinical records."
            recommendation = "Review and redact physician names if patient-doctor privacy is required."

        # 9. QR Codes (Context and Payload Dependent)
        elif d_type == 'qr_code':
            if payload_type in ('upi', 'aadhaar_qr', 'wifi', 'vcard', 'url_sensitive', 'text_sensitive'):
                priority = 'HIGH_PRIORITY'
                action = 'REDACT'
                action_label = 'Redact QR Code'
                suggested_style = 'blackout'
                explanation = f"Scannable digital QR code embedding sensitive data ({d_label})."
                risk_description = "Mobile camera scanners can decode the full hidden payload even if visual text elsewhere on the page is redacted."
                recommendation = "Black out this QR code completely to prevent third-party scanners from extracting the embedded payload."
            elif payload_type == 'url':
                priority = 'INFORMATIONAL'
                action = 'LEAVE'
                action_label = 'Keep QR Link'
                suggested_style = 'blackout'
                explanation = "Directs to a standard public web destination without sensitive authentication parameters."
                risk_description = "Low privacy risk. The destination URL does not appear to contain tokens, passwords, or personal credentials."
                recommendation = "Safe to leave unredacted. Redact only if the destination website is an internal, private portal."
            else:
                priority = 'INFORMATIONAL'
                action = 'LEAVE'
                action_label = 'Keep QR'
                suggested_style = 'blackout'
                explanation = "Digital QR code carrying informational text or non-sensitive data."
                risk_description = "Payload inspection revealed no known credential or high-risk PII patterns."
                recommendation = "Review if the embedded text is appropriate for document recipients. Can safely remain in most sharing scenarios."

        # 10. Fallback for other entities
        else:
            priority = 'REVIEW' if d_risk in ('HIGH', 'CRITICAL') else 'INFORMATIONAL'
            action = 'REVIEW'
            action_label = 'Inspect Item'
            explanation = f"Document element detected under category '{d_cat}'."
            risk_description = "May contain contextual information sensitive to your specific sharing scenario."
            recommendation = "Inspect the highlighted text and decide whether redaction is required."

        return {
            'id': f"rec_{det_id}",
            'finding_id': det_id,
            'page': d_page,
            'label': d_label,
            'category': d_cat,
            'value': d_val,
            'masked': d_masked,
            'bbox': d_bbox,
            'risk': d_risk,
            'priority': priority,
            'priority_info': cls.PRIORITY_LEVELS[priority],
            'action': action,
            'action_label': action_label,
            'suggested_style': suggested_style,
            'explanation': explanation,
            'risk_description': risk_description,
            'recommendation': recommendation,
            'confidence': confidence,
            'confidence_label': 'Confirmed Match' if confidence == 'high' else 'Uncertain / OCR Review',
            'review_required': review_required,
            'status': 'PENDING'  # PENDING | ACCEPTED | DISMISSED
        }

    @classmethod
    def _generate_summary(cls, 
                          detections: List[Dict[str, Any]], 
                          recommendations: List[Dict[str, Any]], 
                          stats: Dict[str, Any], 
                          context: str,
                          file_name: str) -> str:
        """Constructs an accurate, explainable, and non-exaggerated natural language summary."""
        if not detections:
            return (
                f"No sensitive items or automated security risks were identified in '{file_name}'. "
                "The document appears clear for standard distribution under the enabled checks. "
                "Note: Automated detection uses multi-modal heuristic, algorithmic, and OCR analysis and is not 100% exhaustive. "
                "If your document contains handwritten elements, signatures, or visual stamps, "
                "you can use the Manual Draw tool in the toolbar to apply custom redactions."
            )

        total = stats['total']
        high_pri = stats['high_priority']
        review_count = stats['review_recommended']
        info_count = stats['informational']

        # Group counts by clean entity names
        type_summary = []
        counts_by_type = {}
        for r in recommendations:
            lbl = r['label']
            counts_by_type[lbl] = counts_by_type.get(lbl, 0) + 1

        for lbl, count in sorted(counts_by_type.items(), key=lambda x: -x[1]):
            type_summary.append(f"{count} {lbl}" if count > 1 else f"1 {lbl}")

        entities_phrase = ", ".join(type_summary[:3])
        if len(type_summary) > 3:
            entities_phrase += f", and {len(type_summary) - 3} other items"

        summary_parts = []

        if high_pri > 0:
            summary_parts.append(
                f"Your document contains {total} detected item{'s' if total != 1 else ''} ({entities_phrase}), "
                f"including {high_pri} high-priority item{'s' if high_pri != 1 else ''} that should be redacted before sharing in {context} mode."
            )
        elif review_count > 0:
            summary_parts.append(
                f"Your document contains {total} potential item{'s' if total != 1 else ''} ({entities_phrase}). "
                f"Review {'these items' if total != 1 else 'this item'} to decide whether disclosure is appropriate for your recipients."
            )
        else:
            summary_parts.append(
                f"Your document contains {total} informational item{'s' if total != 1 else ''} ({entities_phrase}). "
                "No critical credentials or high-risk identifiers were confirmed by the current scan."
            )

        if stats['uncertain'] > 0:
            summary_parts.append(
                f"{stats['uncertain']} item{'s' if stats['uncertain'] != 1 else ''} {'have' if stats['uncertain'] != 1 else 'has'} unverified formatting or OCR variance and should be inspected manually."
            )

        summary_parts.append("Accept recommendations to select items for redaction, or dismiss any items you choose to keep.")
        summary_parts.append("Note: Automated detection uses multi-modal heuristic, algorithmic, and OCR analysis. It is not 100% exhaustive; please inspect highlighted regions and apply manual redaction if any unflagged confidential details remain.")

        return " ".join(summary_parts)
