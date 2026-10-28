import re
from typing import List, Dict, Any, Tuple

# Verhoeff Algorithm Tables for Indian Aadhaar Checksum Validation
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]

def validate_verhoeff(num_str: str) -> bool:
    """Validates an Indian Aadhaar number using the Verhoeff checksum algorithm."""
    clean = re.sub(r'[\s-]', '', str(num_str))
    if not clean.isdigit() or len(clean) != 12:
        return False
    # Aadhaar cannot start with 0 or 1
    if clean[0] in ('0', '1'):
        return False
        
    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0

def generate_verhoeff_checksum(eleven_digits: str) -> str:
    """Generates the 12th Verhoeff checksum digit for a synthetic 11-digit Aadhaar number."""
    clean = re.sub(r'[\s-]', '', str(eleven_digits))
    if not clean.isdigit() or len(clean) != 11:
        raise ValueError("Must provide exactly 11 digits to calculate Verhoeff checksum")
    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        c = VERHOEFF_D[c][VERHOEFF_P[(i + 1) % 8][digit]]
    checksum_digit = str(VERHOEFF_INV[c])
    return clean + checksum_digit

def validate_luhn(card_number: str) -> bool:
    """Validates credit and debit card numbers using the Luhn mod-10 algorithm."""
    clean = re.sub(r'[\s-]', '', str(card_number))
    if not clean.isdigit() or len(clean) < 13 or len(clean) > 19:
        return False
        
    total = 0
    reverse_digits = [int(d) for d in reversed(clean)]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            total += doubled - 9 if doubled > 9 else doubled
        else:
            total += digit
    return total % 10 == 0

def identify_card_network(card_number: str) -> str:
    clean = re.sub(r'[\s-]', '', card_number)
    if clean.startswith('4'):
        return "Visa"
    elif re.match(r'^(5[1-5]|222[1-9]|22[3-9]|2[3-6]|27[0-1]|2720)', clean):
        return "Mastercard"
    elif clean.startswith(('34', '37')):
        return "American Express"
    elif clean.startswith(('6011', '65', '644', '645')):
        return "Discover"
    elif clean.startswith(('508', '6069', '607', '608', '6521', '652', '6530', '6531')):
        return "RuPay"
    return "Credit/Debit Card"

# PAN Format: 5 letters, 4 numbers, 1 letter. 4th char is entity status.
PAN_VALID_ENTITIES = {'P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'}

class SensitiveDetector:
    """High-accuracy regex detector with algorithmic validators and context-aware classification
    for personally identifiable information (PII). Eliminates false positives on ordinary numbers,
    shell code, and unstructured identifiers.
    """

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self.regexes = {
            'upi_vpa': re.compile(r'\b[a-zA-Z0-9.\-_]{2,64}@(oksbi|okhdfcbank|okaxis|okicici|paytm|ybl|ibl|axl|upi|sbi|hdfcbank|icici|kotak|barodampay|postbank|federal|idfcbank|indus|airtel|gpay|apl)\b', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}\b', re.IGNORECASE),
            'pan': re.compile(r'\b([A-Za-z]{5})[\s-]?([0-9]{4})[\s-]?([A-Za-z]{1})\b'),
            'voter_id': re.compile(r'\b([A-Za-z]{3})[\s-]?([0-9]{7})\b'),
            'driving_licence': re.compile(r'\b([A-Za-z]{2}[\s-]?[0-9]{2}[\s-]?(?:19|20[0-9]{2})[\s-]?[0-9]{7}|[A-Za-z]{2}[ -]?[0-9]{13,15})\b'),
            'passport': re.compile(r'\b([A-PR-WYa-pr-wy][0-9]{7})\b'),
            'dob': re.compile(r'\b(?:DOB|Date\s*of\s*Birth|Year\s*of\s*Birth|जन्म\s*तिथि)\s*[:\-]?\s*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4})\b', re.IGNORECASE),
            'aadhaar_spaced': re.compile(r'\b([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})\b'),
            'aadhaar_compact': re.compile(r'\b([0-9]{12})\b'),
            'aadhaar_masked': re.compile(r'(?:(?<=\s)|(?<=[^\w])|^)([Xx*•]{4})[\s./-]+([Xx*•]{4})[\s./-]+([0-9]{4})(?=\b|[^\w]|$)'),
            'aadhaar_vid': re.compile(r'\b(?:VID\s*[:\-]?)?\s*([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})\b', re.IGNORECASE),
            'card_spaced': re.compile(r'\b(?:\d{4}[\s-]){3}\d{1,4}\b'),
            'card_compact': re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|652\d{13})\b'),
            'indian_phone': re.compile(r'(?:(?<!\w)\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b'),
            'intl_phone': re.compile(r'(?:(?<!\w)\+(?:[1-9]\d{0,2})[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'ssn': re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b'),
            'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            'aws_key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
            'secret_token': re.compile(r'\b(?:ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|AIza[0-9A-Za-z-_]{35}|sk-[a-zA-Z0-9]{32,48})\b')
        }

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """Scans plain text and extracts all validated sensitive entities."""
        if not text:
            return []

        results = []
        seen_spans = set()

        def is_overlapping(start, end):
            return any(max(start, s[0]) < min(end, s[1]) for s in seen_spans)

        # Helper to check if string is likely a calendar date
        def is_calendar_date(s: str) -> bool:
            clean = s.strip()
            return bool(re.match(r'^(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])$', clean) or
                        re.match(r'^(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}$', clean))

        # Check for Aadhaar context keywords in text
        has_aadhaar_context = bool(re.search(
            r'(?:aadhaar|aadhar|adhar|uidai|unique\s*identification|मेरा\s*आधार|मेरी\s*पहचान|enrollment|resident|government\s*of\s*india)',
            text, re.IGNORECASE
        ))

        # 0. Credit / Debit Card Detection with Luhn Checksum & Structured Fallback
        for pat in (self.regexes['card_spaced'], self.regexes['card_compact']):
            for match in pat.finditer(text):
                val = match.group()
                span = (match.start(), match.end())
                if is_overlapping(span[0], span[1]):
                    continue
                clean = re.sub(r'[\s-]', '', val)
                if len(clean) in (13, 15, 16, 19):
                    network = identify_card_network(val)
                    if validate_luhn(val):
                        seen_spans.add(span)
                        results.append({
                            'type': 'credit_card',
                            'label': f'{network} Card',
                            'value': val,
                            'masked': f"****-****-****-{clean[-4:]}",
                            'category': 'Financial Payment',
                            'risk': 'CRITICAL',
                            'char_span': span,
                            'details': f'{network} number verified via Luhn Mod-10 algorithm',
                            'confidence': 'high',
                            'review_required': False
                        })
                    elif pat == self.regexes['card_spaced'] and len(clean) == 16:
                        # 4 groups of 4 digits formatted as card: require financial/card context
                        window = text[max(0, span[0]-40) : min(len(text), span[1]+40)].lower()
                        has_card_context = bool(re.search(r'(?:card|credit|debit|visa|mastercard|amex|payment|cvv|expir)', window))
                        if has_card_context:
                            seen_spans.add(span)
                            results.append({
                                'type': 'credit_card',
                                'label': 'Payment Card Candidate',
                                'value': val,
                                'masked': f"****-****-****-{clean[-4:]}",
                                'category': 'Financial Payment',
                                'risk': 'HIGH',
                                'char_span': span,
                                'details': 'Formatted 16-digit card number candidate',
                                'confidence': 'medium',
                                'review_required': True
                            })

        # 1. Masked Aadhaar UID (e.g. XXXX XXXX 1234 or **** **** 1234)
        for match in self.regexes['aadhaar_masked'].finditer(text):
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                val = match.group()
                results.append({
                    'type': 'aadhaar',
                    'label': 'Masked Aadhaar UID',
                    'value': val,
                    'masked': f"XXXX-XXXX-{val[-4:]}",
                    'category': 'Identity Document',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Masked Aadhaar UIDAI card number with exposed last 4 digits',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.1 16-Digit Virtual ID (VID)
        for match in self.regexes['aadhaar_vid'].finditer(text):
            val = match.group()
            digits = re.sub(r'\D', '', val)
            if len(digits) == 16:
                span = (match.start(), match.end())
                if not is_overlapping(span[0], span[1]):
                    seen_spans.add(span)
                    results.append({
                        'type': 'aadhaar',
                        'label': 'Aadhaar Virtual ID (VID)',
                        'value': val,
                        'masked': f"XXXX-XXXX-XXXX-{digits[-4:]}",
                        'category': 'Identity Document',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': '16-digit UIDAI temporary Virtual ID (VID)',
                        'confidence': 'high',
                        'review_required': False
                    })

        # 1.2 Indian Aadhaar Detection (Spaced & Compact) with Strict Verhoeff Validation & Identifier Fallback
        for pat in (self.regexes['aadhaar_spaced'], self.regexes['aadhaar_compact']):
            for match in pat.finditer(text):
                val = match.group()
                digits = re.sub(r'\D', '', val)
                if len(digits) == 12:
                    span = (match.start(), match.end())
                    if is_overlapping(span[0], span[1]):
                        continue

                    # Filter out calendar dates and invoice years
                    if is_calendar_date(val):
                        continue

                    # Validate Verhoeff checksum (Aadhaar cannot start with 0 or 1)
                    is_checksum_valid = validate_verhoeff(digits)

                    if is_checksum_valid:
                        seen_spans.add(span)
                        results.append({
                            'type': 'aadhaar',
                            'label': 'Indian Aadhaar UID',
                            'value': val,
                            'masked': f"XXXX-XXXX-{digits[-4:]}",
                            'category': 'Identity Document',
                            'risk': 'CRITICAL',
                            'char_span': span,
                            'details': '12-digit UIDAI identity number validated via Verhoeff checksum',
                            'confidence': 'high',
                            'review_required': False
                        })
                    elif has_aadhaar_context:
                        # Cheque failed but explicit Aadhaar context exists in document -> mark as unverified candidate for review
                        seen_spans.add(span)
                        results.append({
                            'type': 'aadhaar',
                            'label': 'Aadhaar UID Candidate (Unverified Checksum)',
                            'value': val,
                            'masked': f"XXXX-XXXX-{digits[-4:]}",
                            'category': 'Identity Document',
                            'risk': 'MEDIUM',
                            'char_span': span,
                            'details': '12-digit number in Aadhaar context (checksum mismatch or OCR distortion)',
                            'confidence': 'low',
                            'review_required': True
                        })
                    elif pat == self.regexes['aadhaar_spaced']:
                        # Spaced 4-4-4 number without Aadhaar context and failed checksum:
                        # Resembles a generic identifier but lacks sufficient evidence for a specific classification.
                        window = text[max(0, span[0]-30) : min(len(text), span[1]+30)].lower()
                        has_id_context = bool(re.search(r'(?:id|identif|no|num|code|ref|serial|sn|order)', window))
                        if has_id_context:
                            seen_spans.add(span)
                            results.append({
                                'type': 'identifier_candidate',
                                'label': 'Unclassified Identifier Candidate',
                                'value': val,
                                'masked': f"XXXX-XXXX-{digits[-4:]}",
                                'category': 'Identity Document',
                                'risk': 'LOW',
                                'char_span': span,
                                'details': 'Formatted 12-digit numeric identifier (unconfirmed classification)',
                                'confidence': 'low',
                                'review_required': True
                            })
                        # If no ID context at all, treat as harmless formatted numbers (e.g. data matrix, coordinates)

        # 2. Indian PAN Card Detection (Requires 4th character entity validation)
        for match in self.regexes['pan'].finditer(text):
            val = match.group()
            clean_pan = re.sub(r'[\s-]', '', val).upper()
            if len(clean_pan) == 10:
                span = (match.start(), match.end())
                if is_overlapping(span[0], span[1]):
                    continue
                entity_char = clean_pan[3]
                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                has_pan_context = bool(re.search(r'(?:pan|tax|income\s*tax|permanent\s*account|itd)', window))
                # Enforce valid Indian Income Tax Department entity codes or nearby PAN context
                if entity_char not in PAN_VALID_ENTITIES and not has_pan_context:
                    continue
                entity_desc = "Individual" if entity_char == 'P' else f"Entity ({entity_char})"
                seen_spans.add(span)
                results.append({
                    'type': 'pan',
                    'label': f'PAN Card ({entity_desc})',
                    'value': val,
                    'masked': f"{clean_pan[:2]}XXXXX{clean_pan[-2:]}",
                    'category': 'Financial Identity',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Permanent Account Number (Entity code: {entity_char})',
                    'confidence': 'high',
                    'review_required': False
                })

        # 2.1 Indian Voter ID (EPIC)
        for match in self.regexes['voter_id'].finditer(text):
            val = match.group()
            clean_epic = re.sub(r'[\s-]', '', val).upper()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                has_voter_context = bool(re.search(r'(?:voter|epic|election|eci|निर्वाचन|पहचान\s*पत्र)', window))
                if has_voter_context:
                    seen_spans.add(span)
                    results.append({
                        'type': 'voter_id',
                        'label': 'Indian Voter ID (EPIC)',
                        'value': val,
                        'masked': f"{clean_epic[:3]}XXXX{clean_epic[-3:]}",
                        'category': 'Identity Document',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': 'Election Commission of India Electoral Photo Identity Card',
                        'confidence': 'high',
                        'review_required': False
                    })

        # 2.2 Indian Driving Licence
        for match in self.regexes['driving_licence'].finditer(text):
            val = match.group()
            clean_dl = re.sub(r'[\s-]', '', val).upper()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]) and len(clean_dl) >= 14:
                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                has_dl_context = bool(re.search(r'(?:licen|dl\b|transport|rto|driving)', window))
                if has_dl_context:
                    seen_spans.add(span)
                    results.append({
                        'type': 'driving_licence',
                        'label': 'Indian Driving Licence',
                        'value': val,
                        'masked': f"{clean_dl[:4]}XXXXXXX{clean_dl[-4:]}",
                        'category': 'Identity Document',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': 'State Transport Authority Driving Licence record',
                        'confidence': 'high',
                        'review_required': False
                    })

        # 2.3 Indian Passport Number
        for match in self.regexes['passport'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                # Verify nearby passport context to avoid false positives on arbitrary letter+7 digits
                if re.search(r'(?:passport|republic\s*of\s*india|nationality)', text, re.IGNORECASE):
                    seen_spans.add(span)
                    results.append({
                        'type': 'passport',
                        'label': 'Indian Passport Number',
                        'value': val,
                        'masked': f"{val[0]}XXXXXX{val[-1]}",
                        'category': 'Identity Document',
                        'risk': 'CRITICAL',
                        'char_span': span,
                        'details': 'Indian Passport travel document identifier',
                        'confidence': 'high',
                        'review_required': False
                    })

        # 2.4 Date of Birth (DOB)
        for match in self.regexes['dob'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'dob',
                    'label': 'Date of Birth (DOB)',
                    'value': val,
                    'masked': 'DOB: **/**/****',
                    'category': 'Identity Document',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Official demographic birth record',
                    'confidence': 'high',
                    'review_required': False
                })

        # 3.5 UPI Virtual Payment Address (VPA)
        for match in self.regexes['upi_vpa'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if is_overlapping(span[0], span[1]):
                continue
            seen_spans.add(span)
            user, handle = val.split('@', 1)
            masked_vpa = (user[:2] + '***' + user[-1]) if len(user) > 3 else user[0] + '***'
            results.append({
                'type': 'upi_vpa',
                'label': 'UPI Payment ID (VPA)',
                'value': val,
                'masked': f"{masked_vpa}@{handle}",
                'category': 'Financial Identity',
                'risk': 'HIGH',
                'char_span': span,
                'details': f'Unified Payments Interface address ({val}) resolves directly to bank account identity',
                'confidence': 'high',
                'review_required': False
            })

        # 4. Email Addresses (Strict validation of structure, TLD, and exclusions)
        for match in self.regexes['email'].finditer(text):
            raw_val = match.group()
            val = raw_val.rstrip('.,;:)]}>"\'')
            if not val or '@' not in val:
                continue
            span = (match.start(), match.start() + len(val))
            if is_overlapping(span[0], span[1]):
                continue

            user, domain = val.split('@', 1)
            # Validate user and domain syntax
            if not user or not domain or '..' in val or user.startswith('.') or user.endswith('.'):
                continue
            if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
                continue
            tld = domain.split('.')[-1]
            if len(tld) < 2 or not tld.isalpha():
                continue
            # Exclude code constructs such as ${#str} or shell variable expansions
            if user.startswith(('#', '$', '{', '<', '!', '"', '\'')):
                continue

            seen_spans.add(span)
            masked_user = (user[0] + '***' + user[-1]) if len(user) > 2 else user[0] + '***'
            results.append({
                'type': 'email',
                'label': 'Email Address',
                'value': val,
                'masked': f"{masked_user}@{domain}",
                'category': 'Contact Information',
                'risk': 'LOW',
                'char_span': span,
                'details': 'Personal or corporate electronic mail address',
                'confidence': 'high',
                'review_required': False
            })

        # 5. US Social Security Number (SSN)
        for match in self.regexes['ssn'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if is_overlapping(span[0], span[1]):
                continue
            seen_spans.add(span)
            results.append({
                'type': 'ssn',
                'label': 'US Social Security Number',
                'value': val,
                'masked': f"***-**-{val[-4:]}",
                'category': 'Identity Document',
                'risk': 'CRITICAL',
                'char_span': span,
                'details': '9-digit US Social Security Number',
                'confidence': 'high',
                'review_required': False
            })

        # 6. Phone Numbers (Indian & International) - Context-aware, filters out dates, prices, units
        for match in self.regexes['indian_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
            if len(clean_digits) in (10, 12):
                span = (match.start(), match.end())
                if is_overlapping(span[0], span[1]) or is_calendar_date(val):
                    continue

                # Repetitive or trivial sequence check (e.g. 9999999999, 1234567890)
                ten_digits = clean_digits[-10:]
                if len(set(ten_digits)) <= 2 or ten_digits in ('1234567890', '0123456789'):
                    continue

                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                # Check for currency or technical measurement units before/after
                if re.search(r'(?:rs\.?|inr|usd|\$|€|₹|bytes|kb|mb|gb|px|pt|fps|mhz)\s*$', text[max(0, span[0]-10):span[0]].lower()):
                    continue

                has_phone_context = bool(re.search(r'(?:phone|tel|mobile|call|ph\b|cell|contact|fax|whatsapp|mob|helpline|संपर्क)', window))
                has_91_prefix = val.strip().startswith('+91') or (clean_digits.startswith('91') and len(clean_digits) == 12)
                is_formatted = bool(re.search(r'[\s-]', val.strip().lstrip('+91').strip()))

                # Only confirm if +91 prefix, phone context, or standard hyphen/space formatting is present
                if has_91_prefix or has_phone_context or is_formatted:
                    seen_spans.add(span)
                    results.append({
                        'type': 'phone',
                        'label': 'Phone Number (IN)',
                        'value': val,
                        'masked': f"+91 XXXXX-{ten_digits[-4:]}",
                        'category': 'Contact Information',
                        'risk': 'MEDIUM',
                        'char_span': span,
                        'details': 'Indian mobile phone number',
                        'confidence': 'high' if (has_91_prefix or has_phone_context) else 'medium',
                        'review_required': not (has_91_prefix or has_phone_context)
                    })

        for match in self.regexes['intl_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
            # Exclude dates, years, and IP addresses
            if len(clean_digits) >= 9 and not is_calendar_date(val):
                if re.match(r'^(?:19|20)\d{2}[-\s]?\d{4}$', val.strip()):
                    continue
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}', val.strip()):
                    continue

                span = (match.start(), match.end())
                if is_overlapping(span[0], span[1]):
                    continue

                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                has_phone_context = bool(re.search(r'(?:phone|tel|mobile|call|ph\b|cell|contact|fax|voice)', window))
                has_plus_prefix = val.strip().startswith('+')
                has_paren_format = bool(re.search(r'\([2-9]\d{2}\)', val))

                # Require plus prefix, standard parenthesis formatting, or phone context
                if has_plus_prefix or has_paren_format or has_phone_context:
                    seen_spans.add(span)
                    results.append({
                        'type': 'phone',
                        'label': 'Phone Number (Intl)',
                        'value': val,
                        'masked': f"***-***-{clean_digits[-4:]}",
                        'category': 'Contact Information',
                        'risk': 'MEDIUM',
                        'char_span': span,
                        'details': 'International standard telephone number',
                        'confidence': 'high' if (has_plus_prefix or has_phone_context) else 'medium',
                        'review_required': False
                    })

        # 7. IPv4 Addresses (Filters out version strings like v1.2.3.4, gcc-11.2.0.1, 0.0.0.0)
        for match in self.regexes['ipv4'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if is_overlapping(span[0], span[1]):
                continue
            if val == '0.0.0.0':
                continue
            # Exclude version strings
            prefix = text[max(0, span[0]-10):span[0]].lower()
            if re.search(r'(?:version|ver|v\b|gcc|python|node|linux|kernel|vmlinuz|pkg)\s*[-_:]?$', prefix):
                continue
            parts = val.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                # Discard multi-digit octets with leading zeroes (like 01.02.03.04)
                if any(len(p) > 1 and p.startswith('0') for p in parts):
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'ip_address',
                    'label': 'IPv4 Address',
                    'value': val,
                    'masked': f"{parts[0]}.*.*.{parts[-1]}",
                    'category': 'Network Infrastructure',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Network host IP address',
                    'confidence': 'high',
                    'review_required': False
                })

        # 8. API Keys, JWT Tokens, and AWS Credentials
        for match in self.regexes['aws_key'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'api_key',
                    'label': 'AWS Access Key ID',
                    'value': val,
                    'masked': f"AKIA****************",
                    'category': 'Cloud Credential',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Amazon Web Services IAM Access Key',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['jwt_token'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'token',
                    'label': 'JSON Web Token (JWT)',
                    'value': val,
                    'masked': f"{val[:10]}...[TRUNCATED JWT TOKEN]...{val[-6:]}",
                    'category': 'Authentication Token',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Encoded JSON Web Token carrying identity and session claims',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['secret_token'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'api_key',
                    'label': 'Secret API Key',
                    'value': val,
                    'masked': f"{val[:5]}****************",
                    'category': 'Security Credential',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Private developer/service API authentication token',
                    'confidence': 'high',
                    'review_required': False
                })

        return results
