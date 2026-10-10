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
    """High-accuracy regex detector with algorithmic validators for personal identifiable information (PII)."""

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self.regexes = {
            'upi_vpa': re.compile(r'\b[a-zA-Z0-9.\-_]{2,64}@(oksbi|okhdfcbank|okaxis|okicici|paytm|ybl|ibl|axl|upi|sbi|hdfcbank|icici|kotak|barodampay|postbank|federal|idfcbank|indus|airtel|gpay|apl)\b', re.IGNORECASE),
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', re.IGNORECASE),
            'pan': re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'),
            'aadhaar_spaced': re.compile(r'\b[2-9]{1}[0-9]{3}[\s-][0-9]{4}[\s-][0-9]{4}\b'),
            'aadhaar_compact': re.compile(r'\b[2-9]{1}[0-9]{11}\b'),
            'card_spaced': re.compile(r'\b(?:\d{4}[\s-]){3}\d{1,4}\b'),
            'card_compact': re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|652\d{13})\b'),
            'indian_phone': re.compile(r'(?:(?<!\w)\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b'),
            'intl_phone': re.compile(r'(?:(?<!\w)\+(?:[1-9]\d{0,2})[-.\s]?)?\(?\d{1,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}\b'),
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

        # 1. Indian Aadhaar Detection (Spaced & Compact) with Verhoeff Validation
        for match in self.regexes['aadhaar_spaced'].finditer(text):
            val = match.group()
            if validate_verhoeff(val):
                span = (match.start(), match.end())
                seen_spans.add(span)
                results.append({
                    'type': 'aadhaar',
                    'label': 'Indian Aadhaar UID',
                    'value': val,
                    'masked': f"XXXX-XXXX-{val[-4:]}",
                    'category': 'Identity Document',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': '12-digit UIDAI identity number validated via Verhoeff checksum'
                })

        for match in self.regexes['aadhaar_compact'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                continue
            if validate_verhoeff(val):
                seen_spans.add(span)
                results.append({
                    'type': 'aadhaar',
                    'label': 'Indian Aadhaar UID',
                    'value': val,
                    'masked': f"XXXXXXXX{val[-4:]}",
                    'category': 'Identity Document',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': '12-digit UIDAI identity number validated via Verhoeff checksum'
                })

        # 2. Indian PAN Card Detection
        for match in self.regexes['pan'].finditer(text):
            val = match.group().upper()
            span = (match.start(), match.end())
            if span in seen_spans:
                continue
            entity_type = val[3]
            entity_desc = "Individual" if entity_type == 'P' else "Company/Entity"
            seen_spans.add(span)
            results.append({
                'type': 'pan',
                'label': f'PAN Card ({entity_desc})',
                'value': val,
                'masked': f"{val[:2]}XXXXX{val[-2:]}",
                'category': 'Financial Identity',
                'risk': 'HIGH',
                'char_span': span,
                'details': f'Permanent Account Number (Entity code: {entity_type})'
            })

        # 3. Credit / Debit Card Detection with Luhn Checksum
        for pat in (self.regexes['card_spaced'], self.regexes['card_compact']):
            for match in pat.finditer(text):
                val = match.group()
                span = (match.start(), match.end())
                if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                    continue
                if validate_luhn(val):
                    network = identify_card_network(val)
                    clean = re.sub(r'[\s-]', '', val)
                    seen_spans.add(span)
                    results.append({
                        'type': 'credit_card',
                        'label': f'{network} Card',
                        'value': val,
                        'masked': f"****-****-****-{clean[-4:]}",
                        'category': 'Financial Payment',
                        'risk': 'CRITICAL',
                        'char_span': span,
                        'details': f'{network} number verified via Luhn Mod-10 algorithm'
                    })

        # 3.5 UPI Virtual Payment Address (VPA) / Payment IDs
        for match in self.regexes['upi_vpa'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
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
                'details': f'Unified Payments Interface address ({val}) resolves directly to bank account identity'
            })

        # 4. Email Addresses
        for match in self.regexes['email'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if span in seen_spans:
                continue
            seen_spans.add(span)
            user, domain = val.split('@', 1)
            masked_user = (user[0] + '***' + user[-1]) if len(user) > 2 else user[0] + '***'
            results.append({
                'type': 'email',
                'label': 'Email Address',
                'value': val,
                'masked': f"{masked_user}@{domain}",
                'category': 'Contact Information',
                'risk': 'LOW',
                'char_span': span,
                'details': 'Personal or corporate electronic mail address'
            })

        # 5. US Social Security Number (SSN) - Evaluate before generic phone numbers
        for match in self.regexes['ssn'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
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
                'details': '9-digit US Social Security Number'
            })

        # 6. Phone Numbers (Indian & International)
        for match in self.regexes['indian_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
            if len(clean_digits) in (10, 12):
                span = (match.start(), match.end())
                if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'phone',
                    'label': 'Phone Number (IN)',
                    'value': val,
                    'masked': f"+91 XXXXX-{clean_digits[-4:]}",
                    'category': 'Contact Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Indian mobile phone number'
                })

        for match in self.regexes['intl_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
            if len(clean_digits) >= 8:
                span = (match.start(), match.end())
                if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'phone',
                    'label': 'Phone Number (Intl)',
                    'value': val,
                    'masked': f"***-***-{clean_digits[-4:]}",
                    'category': 'Contact Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'International standard telephone number'
                })

        # 7. IPv4 Addresses (Filtered to ignore 0.0.0.0, 255.255.255.255, 127.0.0.1 if benign)
        for match in self.regexes['ipv4'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if any(s[0] <= span[0] and span[1] <= s[1] for s in seen_spans):
                continue
            seen_spans.add(span)
            results.append({
                'type': 'ip_address',
                'label': 'IPv4 Address',
                'value': val,
                'masked': f"{val.split('.')[0]}.*.*.{val.split('.')[-1]}",
                'category': 'Network Infrastructure',
                'risk': 'MEDIUM',
                'char_span': span,
                'details': 'Network host IP address'
            })

        # 8. API Keys, JWT Tokens, and AWS Credentials
        for match in self.regexes['aws_key'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            seen_spans.add(span)
            results.append({
                'type': 'api_key',
                'label': 'AWS Access Key ID',
                'value': val,
                'masked': f"AKIA****************",
                'category': 'Cloud Credential',
                'risk': 'CRITICAL',
                'char_span': span,
                'details': 'Amazon Web Services IAM Access Key'
            })

        for match in self.regexes['jwt_token'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            seen_spans.add(span)
            results.append({
                'type': 'token',
                'label': 'JSON Web Token (JWT)',
                'value': val,
                'masked': f"{val[:10]}...[TRUNCATED JWT TOKEN]...{val[-6:]}",
                'category': 'Authentication Token',
                'risk': 'CRITICAL',
                'char_span': span,
                'details': 'Encoded JSON Web Token carrying identity and session claims'
            })

        for match in self.regexes['secret_token'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            seen_spans.add(span)
            results.append({
                'type': 'api_key',
                'label': 'Secret API Key',
                'value': val,
                'masked': f"{val[:5]}****************",
                'category': 'Security Credential',
                'risk': 'CRITICAL',
                'char_span': span,
                'details': 'Private developer/service API authentication token'
            })

        return results
