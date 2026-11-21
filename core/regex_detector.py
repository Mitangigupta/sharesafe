import re
import uuid
from typing import List, Dict, Any, Tuple, Optional

# ============================================================================
# Algorithmic Checksum Validators (Verhoeff, Luhn, IBAN, ABA Routing)
# ============================================================================

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
    """Generates the 12th Verhoeff checksum digit for an 11-digit Aadhaar number."""
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
    """Identifies the credit/debit card payment network from the IIN/BIN prefix."""
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

def validate_iban(iban_str: str) -> bool:
    """Validates an International Bank Account Number (IBAN) using the ISO 7064 mod-97 check."""
    clean = re.sub(r'[\s-]', '', iban_str).upper()
    if len(clean) < 14 or len(clean) > 34:
        return False
    if not re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$', clean):
        return False
    rearranged = clean[4:] + clean[:4]
    digits = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except Exception:
        return False

def validate_aba_routing(routing_str: str) -> bool:
    """Validates a 9-digit US ABA routing transit number using the weighted checksum algorithm."""
    clean = re.sub(r'\D', '', routing_str)
    if len(clean) != 9:
        return False
    d = [int(c) for c in clean]
    checksum = (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + 1 * (d[2] + d[5] + d[8])) % 10
    return checksum == 0

# PAN Format: 5 letters, 4 numbers, 1 letter. 4th char is entity status.
PAN_VALID_ENTITIES = {'P', 'C', 'H', 'F', 'A', 'T', 'B', 'L', 'J', 'G'}

# Non-name blacklist words to prevent false-positive name extractions
BLACKLIST_NAME_WORDS = {
    'hospital', 'clinic', 'statement', 'invoice', 'summary', 'report', 'receipt',
    'system', 'department', 'manual', 'method', 'experiment', 'description',
    'code', 'table', 'doctor', 'physician', 'patient', 'name', 'health', 'care',
    'medical', 'billing', 'services', 'confidential', 'fictional', 'demo', 'card',
    'university', 'center', 'centre', 'office', 'practice', 'associates', 'general',
    'metropolitan', 'authorized', 'signature', 'signature:', 'date', 'account'
}

class SensitiveDetector:
    """Enhanced Multi-Category Sensitive Information Detection Engine.
    
    Identifies sensitive information across four core categories:
    1. Personal Identification (Names, Email, Phone, Addresses, Government IDs)
    2. Financial Information (Cards, Bank Accounts, Payment Info, Financial Identifiers)
    3. Professional & Organisational (Employee IDs, Confidential Markings, Internal References)
    4. Medical Information (Patient IDs, Medical Record Numbers, Diagnoses, Prescriptions)
    
    Combines rule-based regex matching, mathematical checksum algorithms,
    spatial token clustering, and context verification to minimize false positives
    and provide accurate confidence ratings.
    """

    def __init__(self):
        self._compile_patterns()

    def _compile_patterns(self):
        self.regexes = {
            # --- Personal Identification ---
            'name_prefixed': re.compile(
                r'(?i)\b(?:patient(?:\s+name)?|resident(?:\s+name)?|name\s*/\s*resident|cardholder(?:\s+name)?|customer(?:\s+name)?|client(?:\s+name)?|employee(?:\s+name)?|member(?:\s+name)?|(?:full\s+)?name|attending(?:\s+(?:care\s+)?physician|\s+doctor)?|physician|doctor|care\s+provider|surgeon|author|signed\s+by|prepared\s+by|approved\s+by|individual)\s*[:\-]\s*'
                r'([A-Z][a-zA-Z\'.]+(?:\s+[A-Z][a-zA-Z\'.]+){0,3}?(?:,\s*M\.?D\.?|,\s*D\.?O\.?|,\s*M\.?B\.?B\.?S\.?|,\s*Ph\.?D\.?)?)'
                r'(?=\s+(?:invoice|date|email|phone|ssn|department|dept|age|sex|dob|gender|mrn|account|id\b|no\b|ref\b|\$|\d|#|status|balance|amount)|$|[,\n;\r])'
            ),
            'name_honorific': re.compile(
                r'\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Rev\.?|Hon\.?|Shri|Smt)\s+([A-Z][a-zA-Z\'.]+(?:\s+[A-Z][a-zA-Z\'.]+){1,3})\b'
            ),
            'email': re.compile(
                r'\b[A-Za-z0-9](?:[A-Za-z0-9._%+\u2022\u00b7\u2013\u2014~-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.\u2022\u00b7\u2013\u2014~-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}\b',
                re.IGNORECASE
            ),
            'phone_context': re.compile(
                r'(?i)\b(?:phone|tel|telephone|mobile|cell|contact|fax|voice|call)\s*[:\-]?\s*'
                r'(\+?(?:1\s*[-.]?)?\(?[2-9]\d{2}\)?[-.\s]?[0-9OBIl]{3}[-.\s]?[0-9OBIl]{4}(?:\s*(?:ext|x|ext\.)\s*\d{1,5})?)\b'
            ),
            'indian_phone': re.compile(r'(?:(?<!\w)\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b'),
            'intl_phone': re.compile(r'(?:(?<!\w)\+(?:[1-9]\d{0,2})[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[0-9OBIl]{3}[-.\s]?[0-9OBIl]{4}\b'),
            'toll_free_phone': re.compile(r'\b1[-.\s]?(?:800|888|877|866|855|844|833)[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            
            # Addresses
            'address_prefixed': re.compile(
                r'(?i)\b(?:billing\s*address|residential\s*address|permanent\s*address|mailing\s*address|home\s*address|current\s*address|physical\s*address|address)\s*[:\-]\s*'
                r'([^,\n\r]+(?:,[^,\n\r]+){1,3}(?:\s+\d{5}(?:-\d{4})?)?)'
            ),
            'address_street': re.compile(
                r'\b\d{1,5}\s+[A-Za-z0-9.\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Terrace|Ter|Drive|Dr|Court|Ct|Lane|Ln|Way|Place|Pl|Square|Sq|Circle|Cir)\b.*?\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b',
                re.IGNORECASE
            ),
            'address_unit': re.compile(
                r'(?i)\b(?:Apt|Apartment|Suite|Ste|Unit|Flat|PO\s*Box|P\.O\.\s*Box|Plot|House\s*No\.?)\s*#?\s*[0-9A-Za-z\-]+,?\s+[^,\n\r]+(?:,[^,\n\r]+){1,3}\b'
            ),

            # Government IDs
            'ssn': re.compile(r'\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b'),
            'ssn_context': re.compile(r'(?i)\b(?:ssn|social\s*security(?:\s*no\.?|\s*number)?)\s*[:\-]?\s*(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b'),
            'aadhaar_spaced': re.compile(r'\b([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})\b'),
            'aadhaar_compact': re.compile(r'\b([0-9]{12})\b'),
            'aadhaar_masked': re.compile(r'(?:(?<=\s)|(?<=[^\w])|^)([Xx*•]{4})[\s./-]+([Xx*•]{4})[\s./-]+([0-9]{4})(?=\b|[^\w]|$)'),
            'aadhaar_vid': re.compile(r'\b(?:VID\s*[:\-]?)?\s*([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})[\s./-]+([0-9]{4})\b', re.IGNORECASE),
            'pan': re.compile(r'\b([A-Za-z]{5})[\s-]?([0-9]{4})[\s-]?([A-Za-z]{1})\b'),
            'voter_id': re.compile(r'\b([A-Za-z]{3})[\s-]?([0-9]{7})\b'),
            'driving_licence': re.compile(r'\b([A-Za-z]{2}[\s-]?[0-9]{2}[\s-]?(?:19|20[0-9]{2})[\s-]?[0-9]{7}|[A-Za-z]{2}[ -]?[0-9]{13,15})\b'),
            'passport': re.compile(r'\b([A-PR-WYa-pr-wy][0-9]{7})\b'),
            'passport_intl': re.compile(r'(?i)\b(?:passport\s*(?:#|no\.?|num(?:ber)?)?|us\s*passport)\s*[:\-]?\s*([A-Z0-9]{8,9})\b'),
            'nino': re.compile(r'\b([A-CEGHJ-PR-TW-ZQ]{2}\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D])\b'),
            'sin': re.compile(r'(?i)\b(?:sin\b|social\s*insurance(?:\s*no\.?|\s*number)?)\s*[:\-]?\s*(\d{3}[-\s]\d{3}[-\s]\d{3})\b'),
            'driver_license': re.compile(r"(?i)\b(?:(?:state\s*)?driver(?:'?s)?\s*licen(?:se|ce)|dl\s*#|dl\s*no\.?)\s*[:\-]?\s*([A-Za-z0-9\-]{5,18})\b"),
            'dob': re.compile(r'\b(?:DOB|Date\s*of\s*Birth|Year\s*of\s*Birth|जन्म\s*तिथि)\s*[:\-]?\s*(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}|\d{4})\b', re.IGNORECASE),

            # --- Financial Information ---
            'card_spaced': re.compile(r'\b(?:\d{4}[\s-]){3}\d{1,4}\b'),
            'card_compact': re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|652\d{13})\b'),
            'card_context': re.compile(r'(?i)\b(?:card\s*(?:number|no\.?|#)?|card\s*on\s*record|credit\s*card|debit\s*card|payment\s*method|payment\s*card)\s*[:\-]?\s*([0-9\s-]{12,24})\b'),
            'expiration_date': re.compile(r'(?i)\b(?:card\s*expiration|exp(?:ir(?:y|ation|es))?(?:\s*date)?|valid\s*thru|good\s*thru)\s*[:\-]?\s*((?:0[1-9]|1[0-2])\s*[/,\'\-.\s]{1,3}\s*(?:20\d{2}|\d{2}))\b'),
            'cvv_code': re.compile(r'(?i)\b(?:cvv2?|cvc2?|security\s*code|card\s*verification|card\s*code)\s*[:\-]?\s*(\d{3,4})\b'),
            'iban': re.compile(r'\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b'),
            'bank_routing': re.compile(r'(?i)\b(?:routing\s*(?:#|no\.?|number)|aba\s*(?:#|no\.?|routing)|transit\s*#)\s*[:\-]?\s*(\d{9})\b'),
            'bank_sort_code': re.compile(r'(?i)\b(?:sort\s*code|bank\s*code)\s*[:\-]?\s*(\d{2}[-\s]\d{2}[-\s]\d{2})\b'),
            'bank_ifsc': re.compile(r'\b([A-Z]{4}0[A-Z0-9]{6})\b'),
            'bank_account': re.compile(r'(?i)\b(?:bank\s*account(?:\s*#|\s*no\.?|\s*num)?|account\s*number|checking\s*account|savings\s*account|a/c\s*(?:no\.?|#)|acc\s*#)\s*[:\-]?\s*([0-9\s-]{8,20})\b'),
            'upi_vpa': re.compile(r'\b[a-zA-Z0-9.\-_]{2,64}@(oksbi|okhdfcbank|okaxis|okicici|paytm|ybl|ibl|axl|upi|sbi|hdfcbank|icici|kotak|barodampay|postbank|federal|idfcbank|indus|airtel|gpay|apl)\b', re.IGNORECASE),
            'payment_txn': re.compile(r'(?i)\b(?:transaction\s*(?:id|#|ref(?:erence)?)|txn\s*(?:id|#|ref(?:erence)?)|payment\s*(?:ref(?:erence)?|id|#)|utr\s*(?:number|no\.?)|wire\s*ref(?:erence)?)\s*[:\-#]?\s*([A-Za-z0-9\-_]{8,32})\b'),
            'swift_bic': re.compile(r'(?i)\b(?:swift|bic)(?:\s*(?:code|id|no\.?))?\s*[:\-]?\s*([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b'),
            'tax_ein': re.compile(r'(?i)\b(?:ein|employer\s*id(?:\s*no\.?|\s*number)?|tax\s*id(?:\s*no\.?|\s*number)?|federal\s*id)\s*[:\-]?\s*(\d{2}-\d{7})\b'),
            'invoice_token': re.compile(r'(?i)\b(?:invoice(?:\s*#|\s*no\.?|\s*num|\s*id)?|billing\s*ref(?:\s*#)?)\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,24})\b'),

            # --- Professional & Organisational Information ---
            'employee_id': re.compile(r'(?i)\b(?:employee\s*(?:id|#|no\.?|code)|staff(?:\s*member)?(?:\s*(?:id|#|no\.?))?|(?:security\s*)?badge(?:\s*(?:id|#|no\.?|number))?|worker\s*(?:id|#)|emp\s*(?:id|#))\s*[:\-#]?\s*([A-Za-z0-9\-_.]{3,18})\b'),
            'confidential_banner': re.compile(
                r'\b(?:strictly\s+confidential|confidential\s+(?:and|&)\s+proprietary|confidential\s+(?:document|information|report|notice|memo)|internal\s+use\s+only|for\s+internal\s+use\s+only|restricted\s+distribution|highly\s+restricted|do\s+not\s+distribute|trade\s+secret|privileged\s+(?:and|&)\s+confidential|attorney-client\s+privilege|commercially\s+sensitive|non-disclosure\s+agreement|company\s+confidential)\b'
                r'|\b(?:classification|protective\s*marking|security\s*classification|sensitivity)\s*[:\-]\s*(?:confidential|restricted|proprietary|internal|secret)\b'
                r'|\[\s*(?:strictly\s+confidential|confidential|restricted|proprietary|internal\s+use\s+only)\s*\]'
                r'|\*{2,}\s*(?:confidential|restricted|strictly\s+confidential)\s*\*{2,}'
                r'|\b(?:CONFIDENTIAL|RESTRICTED|PROPRIETARY)\b(?!\s*(?:contact|billing|statement|invoice|visa|card|email|phone|hotline|note|portal|demo|doctor|patient|record|medical))',
                re.IGNORECASE
            ),
            'aws_key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
            'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
            'secret_token': re.compile(r'\b(?:ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|AIza[0-9A-Za-z-_]{35}|sk-[a-zA-Z0-9]{32,48})\b'),
            'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
            'internal_reference': re.compile(r'(?i)\b(?:po\s*#|po\s*number|purchase\s*order(?:\s*no\.?)?|project\s*(?:code|id|ref|#)|contract\s*(?:id|#|no\.?)|case\s*(?:number|#|no\.?)|ticket\s*(?:id|#|no\.?)|claim\s*(?:id|#|no\.?))\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,25})\b'),

            # --- Medical Information ---
            'patient_id': re.compile(r'(?i)\b(?:patient\s*(?:identifier|id\b|#|no\.?)|hospital\s*(?:id\b|#|no\.?)|nhs\s*(?:number|#|no\.?)|health\s*card\s*#|uhid)\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,20})\b'),
            'mrn': re.compile(r'(?i)\b(?:mrn\b|medical\s*record(?:\s*number|\s*#|\s*no\.?)|chart\s*(?:#|number|no\.?))\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,20})\b'),
            'health_insurance': re.compile(r'(?i)\b(?:health\s*insurance(?:\s*policy)?(?:\s*(?:#|no\.?|id))?|policy\s*(?:id|#|no\.?)|insurance\s*(?:id|#|no\.?)|member\s*(?:id|#|no\.?)|group\s*(?:number|#)|beneficiary\s*id)\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,20})\b'),
            'prescription_rx': re.compile(r'(?i)\b(?:rx\s*(?:#|number|order)|prescription\s*(?:order|#|number|no\.?))\s*[:\-#]?\s*([A-Za-z0-9\-_.]{4,20})\b'),
            'medical_diagnosis': re.compile(
                r'(?i)\b(?:diagnosis|diagnoses|clinical\s*impression|condition|medical\s*history|chief\s*complaint|assessment|pathology|icd-?(?:9|10)(?:-cm)?)\s*[:\-]\s*'
                r'([A-Za-z0-9\s,./()\-]{4,80})'
                r'(?=[,\n;\r]|\s{2,}|$)'
            ),

            # Infrastructure
            'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),

            # Fallback Identifiers
            'id_candidate': re.compile(
                r'(?i)\b(?:invoice(?:\s*#|\s*no\.?|\s*num|\s*g)?|ref(?:\s*#|\s*no\.?|\s*code)?\b|reference(?:\s*#|\s*no\.?|\s*code)?\b|tracking(?:\s*#|\s*no\.?|\s*code)?\b|national\s*id\b|record\s*id\b)\s*[:\-#.]?\s*([A-Za-z0-9\-_.]{4,20})\b'
            )
        }

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """Scans plain text and extracts validated sensitive entities across all four categories."""
        if not text:
            return []

        results = []
        seen_spans = set()

        def is_overlapping(start, end):
            return any(max(start, s[0]) < min(end, s[1]) for s in seen_spans)

        def is_calendar_date(s: str) -> bool:
            clean = s.strip()
            return bool(re.match(r'^(?:19|20)\d{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12]\d|3[01])$', clean) or
                        re.match(r'^(?:0?[1-9]|[12]\d|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)\d{2}$', clean))

        # Check for Aadhaar context keywords in text
        has_aadhaar_context = bool(re.search(
            r'(?:aadhaar|aadhar|adhar|uidai|unique\s*identification|मेरा\s*आधार|मेरी\s*पहचान|enrollment|resident|government\s*of\s*india)',
            text, re.IGNORECASE
        ))

        # ====================================================================
        # 1. FINANCIAL INFORMATION: Payment Cards, Accounts, Routing, CVV, Exp
        # ====================================================================

        # 1.1 Credit / Debit Cards (Luhn Checksum & Spaced Formats)
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
                            'primary_category': 'Financial Information',
                            'risk': 'CRITICAL',
                            'char_span': span,
                            'details': f'{network} number verified via Luhn Mod-10 algorithm',
                            'confidence': 'high',
                            'review_required': False
                        })
                    elif pat == self.regexes['card_spaced'] and len(clean) in (15, 16):
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
                                'primary_category': 'Financial Information',
                                'risk': 'HIGH',
                                'char_span': span,
                                'details': 'Formatted 16-digit card candidate in financial context',
                                'confidence': 'medium',
                                'review_required': True
                            })

        # 1.2 Context-prefixed Card Number
        for cm in self.regexes['card_context'].finditer(text):
            cval = cm.group(1).strip()
            cspan = cm.span(1)
            if is_overlapping(cspan[0], cspan[1]):
                continue
            cclean = re.sub(r'[\s-]', '', cval)
            if 12 <= len(cclean) <= 19 and cclean.isdigit():
                network = identify_card_network(cval)
                is_valid = validate_luhn(cval)
                seen_spans.add(cspan)
                results.append({
                    'type': 'credit_card',
                    'label': f'{network} Card' if is_valid else 'Payment Card Candidate',
                    'value': cval,
                    'masked': f"****-****-****-{cclean[-4:]}",
                    'category': 'Financial Payment',
                    'primary_category': 'Financial Information',
                    'risk': 'CRITICAL' if is_valid else 'HIGH',
                    'char_span': cspan,
                    'details': f'{network} payment card record' if is_valid else 'Payment card record in card context',
                    'confidence': 'high' if is_valid else 'medium',
                    'review_required': not is_valid
                })

        # 1.3 Card Expiration Date
        for match in self.regexes['expiration_date'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'expiration_date',
                    'label': 'Card Expiration Date',
                    'value': val,
                    'masked': '**/**',
                    'category': 'Financial Payment',
                    'primary_category': 'Financial Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Payment instrument expiration date ({val})',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.4 CVV / CVC Security Code
        for match in self.regexes['cvv_code'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'cvv_code',
                    'label': 'Card CVV/CVC Security Code',
                    'value': val,
                    'masked': '***',
                    'category': 'Financial Payment',
                    'primary_category': 'Financial Information',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Payment card security verification code',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.5 International Bank Account Number (IBAN)
        for match in self.regexes['iban'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            clean_iban = re.sub(r'[\s-]', '', val).upper()
            window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
            has_iban_context = bool(re.search(r'(?:iban|bank|wire|account|transfer|beneficiary)', window))
            is_valid = validate_iban(clean_iban)
            if is_valid or (has_iban_context and len(clean_iban) >= 15):
                seen_spans.add(span)
                results.append({
                    'type': 'iban',
                    'label': 'IBAN Bank Account',
                    'value': val,
                    'masked': f"{clean_iban[:4]}****{clean_iban[-4:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'International Bank Account Number verified via ISO-7064' if is_valid else 'IBAN formatted bank identifier',
                    'confidence': 'high' if is_valid else 'medium',
                    'review_required': not is_valid
                })

        # 1.6 Bank Routing Numbers (ABA, Sort Code, IFSC)
        for match in self.regexes['bank_routing'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                is_aba = validate_aba_routing(val)
                seen_spans.add(span)
                results.append({
                    'type': 'bank_routing',
                    'label': 'ABA Routing Transit Number',
                    'value': val,
                    'masked': f"*****{val[-4:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'US ABA routing transit bank identifier',
                    'confidence': 'high' if is_aba else 'medium',
                    'review_required': not is_aba
                })

        for match in self.regexes['bank_ifsc'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
            has_ifsc_context = bool(re.search(r'(?:ifsc|bank|branch|neft|rtgs|imps|transfer)', window))
            if has_ifsc_context:
                seen_spans.add(span)
                results.append({
                    'type': 'bank_ifsc',
                    'label': 'Indian Bank IFSC Code',
                    'value': val,
                    'masked': f"{val[:4]}0***{val[-2:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Indian Financial System Code identifying bank branch',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.7 Context-prefixed Bank Account Number
        for match in self.regexes['bank_account'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]) or is_calendar_date(val):
                continue
            clean_acc = re.sub(r'[\s-]', '', val)
            if len(clean_acc) >= 8 and clean_acc.isdigit():
                seen_spans.add(span)
                results.append({
                    'type': 'bank_account',
                    'label': 'Bank Account Number',
                    'value': val,
                    'masked': f"******{clean_acc[-4:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Direct financial bank account number (context-confirmed)',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.8 UPI Virtual Payment Address (VPA)
        for match in self.regexes['upi_vpa'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                user, handle = val.split('@', 1)
                masked_vpa = (user[:2] + '***' + user[-1]) if len(user) > 3 else user[0] + '***'
                results.append({
                    'type': 'upi_vpa',
                    'label': 'UPI Payment ID (VPA)',
                    'value': val,
                    'masked': f"{masked_vpa}@{handle}",
                    'category': 'Financial Identity',
                    'primary_category': 'Financial Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Unified Payments Interface address ({val}) resolves to bank identity',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.9 Payment Transaction / Wire Reference
        for match in self.regexes['payment_txn'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 8:
                seen_spans.add(span)
                results.append({
                    'type': 'payment_txn',
                    'label': 'Payment Transaction Reference',
                    'value': val,
                    'masked': f"{val[:2]}****{val[-2:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Financial transaction / wire settlement token',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.10 SWIFT / BIC Banking Code
        for match in self.regexes['swift_bic'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'swift_bic',
                    'label': 'SWIFT / BIC Banking Code',
                    'value': val,
                    'masked': f"{val[:4]}****",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'International financial institution identifier code (SWIFT/BIC)',
                    'confidence': 'high',
                    'review_required': False
                })

        # 1.11 Tax Identification Number / EIN
        for match in self.regexes['tax_ein'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'tax_ein',
                    'label': 'Employer Identification Number (EIN)',
                    'value': val,
                    'masked': f"**-***{val[-4:]}",
                    'category': 'Financial Information',
                    'primary_category': 'Financial Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Official federal business/taxpayer identification number',
                    'confidence': 'high',
                    'review_required': False
                })

        # ====================================================================
        # 2. MEDICAL INFORMATION: Patient IDs, MRNs, Diagnoses, Prescriptions
        # ====================================================================

        # 2.1 Medical Record Number (MRN)
        for match in self.regexes['mrn'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                seen_spans.add(span)
                results.append({
                    'type': 'mrn',
                    'label': 'Medical Record Number (MRN)',
                    'value': val,
                    'masked': f"MRN-****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Medical Information',
                    'primary_category': 'Medical Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Clinical Medical Record Number identifying health demographic chart',
                    'confidence': 'high',
                    'review_required': False
                })

        # 2.2 Patient Identifier / Hospital ID
        for match in self.regexes['patient_id'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                seen_spans.add(span)
                results.append({
                    'type': 'patient_id',
                    'label': 'Patient Identifier',
                    'value': val,
                    'masked': f"{val[:2]}****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Medical Information',
                    'primary_category': 'Medical Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Hospital inpatient/outpatient registration token',
                    'confidence': 'high',
                    'review_required': False
                })

        # 2.3 Health Insurance Policy / Member ID
        for match in self.regexes['health_insurance'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                seen_spans.add(span)
                results.append({
                    'type': 'health_insurance',
                    'label': 'Health Insurance Member ID',
                    'value': val,
                    'masked': f"{val[:2]}****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Medical Information',
                    'primary_category': 'Medical Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Health benefit policy or coverage group identifier',
                    'confidence': 'high',
                    'review_required': False
                })

        # 2.4 Prescription Number (Rx #)
        for match in self.regexes['prescription_rx'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                seen_spans.add(span)
                results.append({
                    'type': 'prescription_rx',
                    'label': 'Prescription Tracking Number (Rx)',
                    'value': val,
                    'masked': f"RX-****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Medical Information',
                    'primary_category': 'Medical Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Pharmacy medication order tracking token',
                    'confidence': 'high',
                    'review_required': False
                })

        # 2.5 Medical Diagnoses & Clinical Findings
        for match in self.regexes['medical_diagnosis'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                # Discard trivial words or punctuation
                if val.lower() in ('none', 'n/a', 'normal', 'pending'):
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'medical_condition',
                    'label': 'Clinical Diagnosis / Medical Condition',
                    'value': val,
                    'masked': '[DIAGNOSIS REDACTED]',
                    'category': 'Medical Information',
                    'primary_category': 'Medical Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Protected Health Information: individual clinical diagnosis or finding',
                    'confidence': 'high',
                    'review_required': False
                })

        # ====================================================================
        # 3. PROFESSIONAL & ORGANISATIONAL: Employee IDs, Banners, References
        # ====================================================================

        # 3.1 Employee Identifier / Staff ID
        for match in self.regexes['employee_id'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 3:
                seen_spans.add(span)
                results.append({
                    'type': 'employee_id',
                    'label': 'Employee Identification Number',
                    'value': val,
                    'masked': f"{val[:1]}****{val[-2:]}" if len(val) > 3 else '****',
                    'category': 'Professional and Organisational Information',
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Corporate personnel employee badge or payroll token',
                    'confidence': 'high',
                    'review_required': False
                })

        # 3.2 Confidential Business Information Markings
        for match in self.regexes['confidential_banner'].finditer(text):
            val = match.group().strip()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'confidential_marking',
                    'label': 'Confidential Business Marking',
                    'value': val,
                    'masked': '[CONFIDENTIAL MARKING REDACTED]',
                    'category': 'Professional and Organisational Information',
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Proprietary business classification banner ({val.upper()})',
                    'confidence': 'high',
                    'review_required': False
                })

        # 3.3 Developer Secrets, AWS Keys, JWTs
        for match in self.regexes['aws_key'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'api_key',
                    'label': 'AWS Access Key ID',
                    'value': val,
                    'masked': "AKIA****************",
                    'category': 'Cloud Credential',
                    'primary_category': 'Professional and Organisational Information',
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
                    'primary_category': 'Professional and Organisational Information',
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
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Private developer/service API authentication token',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['private_key'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'private_key',
                    'label': 'Private Cryptographic Key',
                    'value': val,
                    'masked': '-----BEGIN [REDACTED PRIVATE KEY]-----',
                    'category': 'Security Credential',
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Asymmetric private key header exposing cryptographic identity',
                    'confidence': 'high',
                    'review_required': False
                })

        # 3.4 Internal Reference Numbers (PO #, Project Code, Contract #)
        for match in self.regexes['internal_reference'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 4:
                prefix = text[match.start():match.start(1)].lower()
                if 'po' in prefix or 'purchase' in prefix:
                    lbl = 'Purchase Order Number'
                elif 'project' in prefix:
                    lbl = 'Project Reference Code'
                elif 'contract' in prefix:
                    lbl = 'Contract Agreement Number'
                elif 'case' in prefix:
                    lbl = 'Internal Case Number'
                else:
                    lbl = 'Internal Reference Number'

                seen_spans.add(span)
                results.append({
                    'type': 'internal_reference',
                    'label': lbl,
                    'value': val,
                    'masked': f"{val[:2]}****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Professional and Organisational Information',
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'LOW',
                    'char_span': span,
                    'details': f'Internal enterprise organizational record ({lbl})',
                    'confidence': 'high',
                    'review_required': False
                })

        # ====================================================================
        # 4. PERSONAL IDENTIFICATION: Names, Addresses, Gov IDs, Contact
        # ====================================================================

        # 4.1 US Social Security Number (SSN)
        for pat in (self.regexes['ssn'], self.regexes['ssn_context']):
            for match in pat.finditer(text):
                val = match.group(1) if pat == self.regexes['ssn_context'] else match.group()
                span = match.span(1) if pat == self.regexes['ssn_context'] else (match.start(), match.end())
                if is_overlapping(span[0], span[1]):
                    continue
                clean_ssn = re.sub(r'\D', '', val)
                if len(clean_ssn) != 9:
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'ssn',
                    'label': 'US Social Security Number',
                    'value': val,
                    'masked': f"***-**-{clean_ssn[-4:]}",
                    'category': 'Identity Document',
                    'primary_category': 'Personal Identification',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': '9-digit US Social Security Number',
                    'confidence': 'high',
                    'review_required': False
                })

        # 4.2 Indian Aadhaar UID (Masked, VID, and 12-Digit Verhoeff)
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
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Masked Aadhaar UIDAI card number with exposed last 4 digits',
                    'confidence': 'high',
                    'review_required': False
                })

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
                        'primary_category': 'Personal Identification',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': '16-digit UIDAI temporary Virtual ID (VID)',
                        'confidence': 'high',
                        'review_required': False
                    })

        for pat in (self.regexes['aadhaar_spaced'], self.regexes['aadhaar_compact']):
            for match in pat.finditer(text):
                val = match.group()
                digits = re.sub(r'\D', '', val)
                if len(digits) == 12:
                    span = (match.start(), match.end())
                    if is_overlapping(span[0], span[1]) or is_calendar_date(val):
                        continue
                    is_checksum_valid = validate_verhoeff(digits)
                    is_compact = (pat == self.regexes['aadhaar_compact'])
                    if is_compact and not has_aadhaar_context:
                        continue
                    if is_checksum_valid:
                        seen_spans.add(span)
                        results.append({
                            'type': 'aadhaar',
                            'label': 'Indian Aadhaar UID',
                            'value': val,
                            'masked': f"XXXX-XXXX-{digits[-4:]}",
                            'category': 'Identity Document',
                            'primary_category': 'Personal Identification',
                            'risk': 'CRITICAL',
                            'char_span': span,
                            'details': '12-digit UIDAI identity number validated via Verhoeff checksum',
                            'confidence': 'high',
                            'review_required': False
                        })
                    elif has_aadhaar_context:
                        seen_spans.add(span)
                        results.append({
                            'type': 'aadhaar',
                            'label': 'Aadhaar UID Candidate (Unverified Checksum)',
                            'value': val,
                            'masked': f"XXXX-XXXX-{digits[-4:]}",
                            'category': 'Identity Document',
                            'primary_category': 'Personal Identification',
                            'risk': 'MEDIUM',
                            'char_span': span,
                            'details': '12-digit number in Aadhaar context (checksum mismatch or OCR distortion)',
                            'confidence': 'low',
                            'review_required': True
                        })

        # 4.3 Indian PAN Card
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
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Permanent Account Number (Entity code: {entity_char})',
                    'confidence': 'high',
                    'review_required': False
                })

        # 4.4 Voter ID (EPIC), Driver's License, Passports, UK NINO, Canadian SIN
        for match in self.regexes['voter_id'].finditer(text):
            val = match.group()
            clean_epic = re.sub(r'[\s-]', '', val).upper()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                if re.search(r'(?:voter|epic|election|eci|निर्वाचन|पहचान\s*पत्र)', window):
                    seen_spans.add(span)
                    results.append({
                        'type': 'voter_id',
                        'label': 'Indian Voter ID (EPIC)',
                        'value': val,
                        'masked': f"{clean_epic[:3]}XXXX{clean_epic[-3:]}",
                        'category': 'Identity Document',
                        'primary_category': 'Personal Identification',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': 'Election Commission of India Electoral Photo Identity Card',
                        'confidence': 'high',
                        'review_required': False
                    })

        for match in self.regexes['driving_licence'].finditer(text):
            val = match.group()
            clean_dl = re.sub(r'[\s-]', '', val).upper()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]) and len(clean_dl) >= 14:
                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                if re.search(r'(?:licen|dl\b|transport|rto|driving)', window):
                    seen_spans.add(span)
                    results.append({
                        'type': 'driving_licence',
                        'label': 'Indian Driving Licence',
                        'value': val,
                        'masked': f"{clean_dl[:4]}XXXXXXX{clean_dl[-4:]}",
                        'category': 'Identity Document',
                        'primary_category': 'Personal Identification',
                        'risk': 'HIGH',
                        'char_span': span,
                        'details': 'State Transport Authority Driving Licence record',
                        'confidence': 'high',
                        'review_required': False
                    })

        for match in self.regexes['driver_license'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 5:
                seen_spans.add(span)
                results.append({
                    'type': 'driving_licence',
                    'label': "State Driver's License",
                    'value': val,
                    'masked': f"{val[:2]}****{val[-2:]}" if len(val) > 4 else '****',
                    'category': 'Identity Document',
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': "Motor vehicle department driver's license number",
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['passport'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                if re.search(r'(?:passport|republic\s*of\s*india|nationality)', text, re.IGNORECASE):
                    seen_spans.add(span)
                    results.append({
                        'type': 'passport',
                        'label': 'Indian Passport Number',
                        'value': val,
                        'masked': f"{val[0]}XXXXXX{val[-1]}",
                        'category': 'Identity Document',
                        'primary_category': 'Personal Identification',
                        'risk': 'CRITICAL',
                        'char_span': span,
                        'details': 'Indian Passport travel document identifier',
                        'confidence': 'high',
                        'review_required': False
                    })

        for match in self.regexes['passport_intl'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 7:
                seen_spans.add(span)
                results.append({
                    'type': 'passport',
                    'label': 'Passport Number',
                    'value': val,
                    'masked': f"{val[0]}*****{val[-1]}",
                    'category': 'Identity Document',
                    'primary_category': 'Personal Identification',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'International passport document identifier',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['nino'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
            if re.search(r'(?:national\s*insurance|nino|hmrc|uk)', window):
                seen_spans.add(span)
                results.append({
                    'type': 'nino',
                    'label': 'UK National Insurance Number (NINO)',
                    'value': val,
                    'masked': f"{val[:2]} ** ** ** {val[-1]}",
                    'category': 'Identity Document',
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'HM Revenue & Customs National Insurance Number',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['sin'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]):
                seen_spans.add(span)
                results.append({
                    'type': 'sin',
                    'label': 'Canadian Social Insurance Number (SIN)',
                    'value': val,
                    'masked': '***-***-' + re.sub(r'\D', '', val)[-3:],
                    'category': 'Identity Document',
                    'primary_category': 'Personal Identification',
                    'risk': 'CRITICAL',
                    'char_span': span,
                    'details': 'Employment and Social Development Canada Social Insurance Number',
                    'confidence': 'high',
                    'review_required': False
                })

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
                    'primary_category': 'Personal Identification',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Official demographic birth record',
                    'confidence': 'high',
                    'review_required': False
                })

        # 4.5 Personal Names (Prefixed and Honorific)
        for match in self.regexes['name_prefixed'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            words_in_name = val.split()
            if not words_in_name or len(words_in_name) > 4:
                continue
            if all(w.lower().rstrip('.,') in BLACKLIST_NAME_WORDS for w in words_in_name):
                continue
            matched_prefix = text[match.start():match.start(1)].lower()
            if 'patient' in matched_prefix:
                det_type = 'name'
                label = 'Patient Name'
                category = 'Personal Identity'
                primary_category = 'Medical Information'
            elif 'physician' in matched_prefix or 'doctor' in matched_prefix or 'care' in matched_prefix or 'surgeon' in matched_prefix:
                det_type = 'attending_physician'
                label = 'Attending Physician Name'
                category = 'Personal Identity'
                primary_category = 'Medical Information'
            elif 'resident' in matched_prefix:
                det_type = 'name'
                label = 'Resident Name'
                category = 'Personal Identity'
                primary_category = 'Personal Identification'
            elif 'cardholder' in matched_prefix:
                det_type = 'name'
                label = 'Cardholder Name'
                category = 'Personal Identity'
                primary_category = 'Financial Information'
            elif 'employee' in matched_prefix:
                det_type = 'name'
                label = 'Employee Name'
                category = 'Personal Identity'
                primary_category = 'Professional and Organisational Information'
            else:
                det_type = 'name'
                label = 'Person Name'
                category = 'Personal Identity'
                primary_category = 'Personal Identification'

            seen_spans.add(span)
            masked_name = f"{words_in_name[0][0]}*** {words_in_name[-1][0]}***" if len(words_in_name) >= 2 else f"{val[0]}***"
            results.append({
                'type': det_type,
                'label': label,
                'value': val,
                'masked': masked_name,
                'category': category,
                'primary_category': primary_category,
                'risk': 'HIGH',
                'char_span': span,
                'details': f'Individual identifying name ({label})',
                'confidence': 'high',
                'review_required': False
            })

        for match in self.regexes['name_honorific'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            words_in_name = val.split()
            if not words_in_name or len(words_in_name) > 4:
                continue
            if any(w.lower().rstrip('.,') in BLACKLIST_NAME_WORDS for w in words_in_name):
                continue
            seen_spans.add(span)
            masked_name = f"{words_in_name[0][0]}*** {words_in_name[-1][0]}***" if len(words_in_name) >= 2 else f"{val[0]}***"
            results.append({
                'type': 'name',
                'label': 'Person Name (Honorific)',
                'value': val,
                'masked': masked_name,
                'category': 'Personal Identity',
                'primary_category': 'Personal Identification',
                'risk': 'HIGH',
                'char_span': span,
                'details': 'Individual identifying name preceded by social/professional title',
                'confidence': 'high',
                'review_required': False
            })

        # 4.6 Residential and Billing Addresses
        for match in self.regexes['address_prefixed'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if not is_overlapping(span[0], span[1]) and len(val) >= 10:
                seen_spans.add(span)
                label = 'Billing Address' if re.search(r'billing', match.group(0), re.IGNORECASE) else 'Residential Address'
                results.append({
                    'type': 'address',
                    'label': label,
                    'value': val,
                    'masked': val[:4] + '*** (Redacted Address)',
                    'category': 'Location & Address',
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Physical {label.lower()}',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['address_street'].finditer(text):
            val = match.group().strip()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]) and len(val) >= 10:
                seen_spans.add(span)
                is_billing = bool(re.search(r'billing', text[max(0, span[0]-35):span[0]], re.IGNORECASE))
                label = 'Billing Address' if is_billing else 'Residential / Postal Address'
                results.append({
                    'type': 'address',
                    'label': label,
                    'value': val,
                    'masked': val[:4] + '*** (Redacted Address)',
                    'category': 'Location & Address',
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': f'Physical {label.lower()}',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['address_unit'].finditer(text):
            val = match.group().strip()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]) and len(val) >= 8:
                seen_spans.add(span)
                results.append({
                    'type': 'address',
                    'label': 'Residential Unit Address',
                    'value': val,
                    'masked': val[:4] + '*** (Redacted Address)',
                    'category': 'Location & Address',
                    'primary_category': 'Personal Identification',
                    'risk': 'HIGH',
                    'char_span': span,
                    'details': 'Residential apartment, suite, flat, or PO box address',
                    'confidence': 'high',
                    'review_required': False
                })

        # 4.7 Email Addresses
        for match in self.regexes['email'].finditer(text):
            raw_val = match.group()
            val = raw_val.rstrip('.,;:)]}>"\'')
            if not val or '@' not in val:
                continue
            span = (match.start(), match.start() + len(val))
            if is_overlapping(span[0], span[1]):
                continue

            user, domain = val.split('@', 1)
            norm_domain = re.sub(r'[\u2022\u00b7]', '.', domain)
            norm_domain = re.sub(r'[\u2013\u2014~_]', '-', norm_domain)
            norm_user = re.sub(r'[\u2022\u00b7]', '.', user)
            norm_user = re.sub(r'[\u2013\u2014~_]', '-', norm_user)

            if not norm_user or not norm_domain or '..' in norm_domain or norm_user.startswith('.') or norm_user.endswith('.'):
                continue
            if '.' not in norm_domain or norm_domain.startswith('.') or norm_domain.endswith('.'):
                continue
            tld = norm_domain.split('.')[-1]
            if len(tld) < 2 or not tld.isalpha():
                continue
            if norm_user.startswith(('#', '$', '{', '<', '!', '"', '\'')):
                continue

            seen_spans.add(span)
            masked_user = (norm_user[0] + '***' + norm_user[-1]) if len(norm_user) > 2 else norm_user[0] + '***'
            results.append({
                'type': 'email',
                'label': 'Email Address',
                'value': val,
                'masked': f"{masked_user}@{norm_domain}",
                'category': 'Contact Information',
                'primary_category': 'Personal Identification',
                'risk': 'LOW',
                'char_span': span,
                'details': 'Personal or corporate electronic mail address',
                'confidence': 'high',
                'review_required': False
            })

        # 4.8 Phone Numbers (Context-Prefixed, Toll-Free, Indian, International)
        for pm in self.regexes['phone_context'].finditer(text):
            pval = pm.group(1).strip()
            pspan = pm.span(1)
            if is_overlapping(pspan[0], pspan[1]):
                continue
            norm_num = pval.replace('O', '0').replace('B', '8').replace('l', '1').replace('I', '1')
            pclean = re.sub(r'\D', '', norm_num)
            if len(pclean) >= 7:
                seen_spans.add(pspan)
                results.append({
                    'type': 'phone',
                    'label': 'Phone Number (Intl)',
                    'value': pval,
                    'masked': f"***-***-{pclean[-4:]}",
                    'category': 'Contact Information',
                    'primary_category': 'Personal Identification',
                    'risk': 'MEDIUM',
                    'char_span': pspan,
                    'details': 'Telephone contact line (context-confirmed)',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['toll_free_phone'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if not is_overlapping(span[0], span[1]):
                clean = re.sub(r'\D', '', val)
                seen_spans.add(span)
                results.append({
                    'type': 'phone',
                    'label': 'Toll-Free Phone Number',
                    'value': val,
                    'masked': f"1-800-***-{clean[-4:]}",
                    'category': 'Contact Information',
                    'primary_category': 'Personal Identification',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Toll-free voice communication line',
                    'confidence': 'high',
                    'review_required': False
                })

        for match in self.regexes['indian_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
            if len(clean_digits) in (10, 12):
                span = (match.start(), match.end())
                if is_overlapping(span[0], span[1]) or is_calendar_date(val):
                    continue
                ten_digits = clean_digits[-10:]
                if len(set(ten_digits)) <= 2 or ten_digits in ('1234567890', '0123456789'):
                    continue

                window = text[max(0, span[0]-35) : min(len(text), span[1]+35)].lower()
                if re.search(r'(?:rs\.?|inr|usd|\$|€|₹|bytes|kb|mb|gb|px|pt|fps|mhz)\s*$', text[max(0, span[0]-10):span[0]].lower()):
                    continue

                has_phone_context = bool(re.search(r'(?:phone|tel|mobile|call|ph\b|cell|contact|fax|whatsapp|mob|helpline|संपर्क)', window))
                has_91_prefix = val.strip().startswith('+91') or (clean_digits.startswith('91') and len(clean_digits) == 12)
                is_formatted = bool(re.search(r'[\s-]', val.strip().lstrip('+91').strip()))

                if has_91_prefix or has_phone_context or is_formatted:
                    seen_spans.add(span)
                    results.append({
                        'type': 'phone',
                        'label': 'Phone Number (IN)',
                        'value': val,
                        'masked': f"+91 XXXXX-{ten_digits[-4:]}",
                        'category': 'Contact Information',
                        'primary_category': 'Personal Identification',
                        'risk': 'MEDIUM',
                        'char_span': span,
                        'details': 'Indian mobile phone number',
                        'confidence': 'high' if (has_91_prefix or has_phone_context) else 'medium',
                        'review_required': not (has_91_prefix or has_phone_context)
                    })

        for match in self.regexes['intl_phone'].finditer(text):
            val = match.group()
            clean_digits = re.sub(r'\D', '', val)
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
                if has_plus_prefix or has_paren_format or has_phone_context:
                    seen_spans.add(span)
                    results.append({
                        'type': 'phone',
                        'label': 'Phone Number (Intl)',
                        'value': val,
                        'masked': f"***-***-{clean_digits[-4:]}",
                        'category': 'Contact Information',
                        'primary_category': 'Personal Identification',
                        'risk': 'MEDIUM',
                        'char_span': span,
                        'details': 'International standard telephone number',
                        'confidence': 'high' if (has_plus_prefix or has_phone_context) else 'medium',
                        'review_required': False
                    })

        # ====================================================================
        # 5. INFRASTRUCTURE & FALLBACK IDENTIFIERS
        # ====================================================================

        # 5.1 IPv4 Addresses
        for match in self.regexes['ipv4'].finditer(text):
            val = match.group()
            span = (match.start(), match.end())
            if is_overlapping(span[0], span[1]) or val == '0.0.0.0':
                continue
            prefix = text[max(0, span[0]-10):span[0]].lower()
            if re.search(r'(?:version|ver|v\b|gcc|python|node|linux|kernel|vmlinuz|pkg)\s*[-_:]?$', prefix):
                continue
            parts = val.split('.')
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                if any(len(p) > 1 and p.startswith('0') for p in parts):
                    continue
                seen_spans.add(span)
                results.append({
                    'type': 'ip_address',
                    'label': 'IPv4 Address',
                    'value': val,
                    'masked': f"{parts[0]}.*.*.{parts[-1]}",
                    'category': 'Network Infrastructure',
                    'primary_category': 'Professional and Organisational Information',
                    'risk': 'MEDIUM',
                    'char_span': span,
                    'details': 'Network host IP address',
                    'confidence': 'high',
                    'review_required': False
                })

        # 5.2 General Invoices & Unclassified Identifiers
        for match in self.regexes['id_candidate'].finditer(text):
            val = match.group(1).strip()
            span = match.span(1)
            if is_overlapping(span[0], span[1]):
                continue
            clean_id = re.sub(r'[\s\-_.#]', '', val)
            if len(clean_id) < 4:
                continue
            seen_spans.add(span)
            masked_id = (val[:2] + '****' + val[-2:]) if len(val) > 4 else '****'
            matched_prefix = text[match.start():match.start(1)].lower()
            is_invoice = 'invoice' in matched_prefix
            label = 'Invoice Number' if is_invoice else 'Identifier Candidate'
            risk = 'MEDIUM' if is_invoice else 'LOW'
            conf = 'high' if is_invoice else 'medium'
            review_req = not is_invoice
            results.append({
                'type': 'identifier_candidate',
                'label': label,
                'value': val,
                'masked': masked_id,
                'category': 'Identity Document',
                'primary_category': 'Financial Information' if is_invoice else 'Personal Identification',
                'risk': risk,
                'char_span': span,
                'details': f'Official record identifier ({label} #{val})',
                'confidence': conf,
                'review_required': review_req
            })

        for r in results:
            if 'id' not in r:
                r['id'] = f"det_{uuid.uuid4().hex[:8]}"

        return results
