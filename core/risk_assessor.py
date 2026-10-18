from typing import List, Dict, Any

class RiskAssessor:
    """Evaluates privacy and security threats of detected entities with context-aware weighting (Academic, Professional, Private, Public)."""

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
        for d in detections:
            risk = d.get('risk', 'LOW').upper()
            if risk in counts:
                counts[risk] += 1
            else:
                counts['LOW'] += 1
                risk = 'LOW'

            raw_score += cls.BASE_WEIGHTS.get(risk, 4)
            cat = d.get('category', 'General PII')
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Apply sharing context multiplier
        adjusted_score = int(round(raw_score * context_info['multiplier']))
        score = min(100, adjusted_score)

        # Context-aware risk thresholds
        if counts['CRITICAL'] > 0 or score >= 60:
            level = 'CRITICAL'
            badge_color = '#A74440'  # Deep Red for serious findings
            if context == 'public':
                recommendation = f"CRITICAL EXPOSURE: {counts['CRITICAL']} Critical & {counts['HIGH']} High risk entities detected. Sharing publicly without redaction risks identity theft or credential hijacking."
            else:
                recommendation = f"CRITICAL EXPOSURE: Found {counts['CRITICAL']} Critical and {counts['HIGH']} High risk entities. Redaction is strongly recommended before sharing."
        elif counts['HIGH'] > 0 or score >= 35:
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
