from typing import List, Dict, Any

class RiskAssessor:
    """Evaluates privacy and security threats of detected entities with context-aware weighting (Academic, Professional, Private, Public).
    
    SCORING RULES:
    1. Base Weights:
       - Confirmed CRITICAL (SSN, verified Aadhaar, Luhn-valid Credit Cards, AWS keys, JWT): 35 points
       - Confirmed HIGH (PAN, Voter ID, DL, Wi-Fi password, UPI, Payment card candidate): 20 points
       - Confirmed MEDIUM (Phone numbers, IPv4, DOB): 10 points
       - Confirmed LOW (Email, standard URLs, general text QR): 4 points
       - Uncertain/Review-Needed Candidates (Unclassified ID, unverified checksum): 4 points
       - Informational QR (ordinary URL / plain text payload): 2 points
    2. Context Multipliers:
       - Public: 1.3x (elevated scrutiny for public web destinations)
       - Professional: 1.1x (enterprise data protection)
       - Academic: 1.0x (standard baseline for coursework & lab manuals)
       - Private: 0.85x (trusted peer sharing)
    3. Severity Thresholds:
       - CRITICAL: >= 60 score OR at least 1 confirmed CRITICAL finding
       - HIGH: >= 35 score OR at least 1 confirmed HIGH finding
       - MEDIUM: >= 15 score OR at least 1 confirmed MEDIUM finding
       - LOW: > 0 score
       - CLEAN: 0 findings / 0 score
    """

    BASE_WEIGHTS = {
        'CRITICAL': 35,
        'HIGH': 20,
        'MEDIUM': 10,
        'LOW': 4
    }

    CONTEXT_MULTIPLIERS = {
        'public': {
            'multiplier': 1.3,
            'desc': 'Public Sharing Mode: Maximum scrutiny applied for publicly accessible destinations (Social Media, Reddit, GitHub).'
        },
        'professional': {
            'multiplier': 1.1,
            'desc': 'Professional Sharing Mode: Elevated protection for enterprise credentials, client records, and financial invoices.'
        },
        'academic': {
            'multiplier': 1.0,
            'desc': 'Academic Sharing Mode: Tuned for student projects, coursework, and research papers with PII protection.'
        },
        'private': {
            'multiplier': 0.85,
            'desc': 'Private Sharing Mode: Standard protection for sharing with trusted peers and close contacts.'
        }
    }

    @classmethod
    def assess(cls, detections: List[Dict[str, Any]], context: str = 'academic') -> Dict[str, Any]:
        """Calculates risk level, composite score, breakdown counts, and context-specific security recommendations."""
        context = (context or 'academic').lower()
        if context not in cls.CONTEXT_MULTIPLIERS:
            context = 'academic'

        context_info = cls.CONTEXT_MULTIPLIERS[context]

        if not detections:
            return {
                'level': 'CLEAN',
                'badge_color': '#647C70',  # Muted Sage
                'score': 0,
                'total_entities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'category_breakdown': {},
                'recommendation': 'No findings detected by the enabled checks. Document appears clear for distribution.',
                'can_share_safely': True,
                'sharing_context': context,
                'context_desc': context_info['desc']
            }

        counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        category_counts = {}

        raw_score = 0
        confirmed_critical = 0
        confirmed_high = 0

        for d in detections:
            risk = d.get('risk', 'LOW').upper()
            if risk not in counts:
                risk = 'LOW'

            counts[risk] += 1
            cat = d.get('category', 'General PII')
            category_counts[cat] = category_counts.get(cat, 0) + 1

            is_uncertain = d.get('review_required', False) or d.get('confidence') == 'low'
            payload_type = d.get('payload_type')

            if is_uncertain:
                # Diminished weight for review-needed items to avoid score inflation
                raw_score += 4
            elif payload_type in ('url', 'text') and risk == 'LOW':
                # Harmless informational QR payload
                raw_score += 2
            else:
                raw_score += cls.BASE_WEIGHTS.get(risk, 4)
                if risk == 'CRITICAL':
                    confirmed_critical += 1
                elif risk == 'HIGH':
                    confirmed_high += 1

        # Apply sharing context multiplier
        adjusted_score = int(round(raw_score * context_info['multiplier']))
        score = min(100, adjusted_score)

        # Context-aware risk thresholds
        if confirmed_critical > 0 or score >= 60:
            level = 'CRITICAL'
            badge_color = '#A74440'  # Deep Red for serious findings
            if context == 'public':
                recommendation = f"CRITICAL EXPOSURE: {counts['CRITICAL']} Critical & {counts['HIGH']} High risk entities detected. Sharing publicly without redaction risks identity theft or credential hijacking."
            else:
                recommendation = f"CRITICAL EXPOSURE: Found {counts['CRITICAL']} Critical and {counts['HIGH']} High risk entities. Redaction is strongly recommended before sharing."
        elif confirmed_high > 0 or score >= 35:
            level = 'HIGH'
            badge_color = '#C96D67'  # Muted Coral
            recommendation = f"HIGH PRIVACY RISK: Contains {counts['HIGH']} high-sensitivity identity or credential records. Sanitization recommended to maintain confidentiality."
        elif counts['MEDIUM'] > 0 or score >= 15:
            level = 'MEDIUM'
            badge_color = '#B27329'  # Warm Amber
            recommendation = f"MODERATE PRIVACY RISK: {counts['MEDIUM']} direct contact or network identifiers found. Review and sanitize items you do not wish to disclose."
        else:
            level = 'LOW'
            badge_color = '#5B7470'  # Muted Slate-Sage
            recommendation = f"LOW SENSITIVITY: Found {counts['LOW']} general items (email or web links). Safe for trusted sharing, or sanitize for anonymity."

        return {
            'level': level,
            'badge_color': badge_color,
            'score': score,
            'total_entities': len(detections),
            'critical_count': counts['CRITICAL'],
            'high_count': counts['HIGH'],
            'medium_count': counts['MEDIUM'],
            'low_count': counts['LOW'],
            'category_breakdown': category_counts,
            'recommendation': recommendation,
            'can_share_safely': False,
            'sharing_context': context,
            'context_desc': context_info['desc']
        }
