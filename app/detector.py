

import re
from typing import Dict, List

# --- PATTERNS ---
URGENCY_PATTERNS = ["urgent", "immediately", "now", "today", "within 24 hours", "expire", "blocked", "verify", "kyc", "suspended", "action required", "deadline", "alert", "final notice"]
AUTHORITY_PATTERNS = ["police", "court", "rbi", "income tax", "official", "cbi", "officer", "bank manager", "cyber cell", "enforcement", "judge"]
FINANCIAL_PATTERNS = ["p@y","pay", "upi", "amount", "transfer", "refund", "deposit", "fee", "bank", "account", "credit", "debit", "wallet", "pin", "details", "balance", "money", "cash", "loan"]
THREAT_PATTERNS = ["jail", "arrest", "suspend", "disconnect", "illegal", "case file", "warrant", "legal action", "fir", "fine", "penalty", "block", "cut off", "detain", "prosecute"]
LOTTERY_PATTERNS = ["lottery", "won", "prize", "congratulations", "claim", "winner", "lucky", "cash reward", "crore", "lakh", "jackpot"]
IMPERSONATION_PATTERNS = ["mom", "dad", "son", "daughter", "accident", "hospital", "lost phone", "new number", "emergency", "help", "friend", "family"]
JOB_PATTERNS = ["j0b","hiring", "part time", "part-time", "wfh", "work from home", "salary", "daily income", "earn", "telegram", "hr", "vacancy", "job offer"]
UTILITY_PATTERNS = ["electricity", "power", "bill", "consumer number", "light", "connection", "meter", "update"]
SEXTORTION_PATTERNS = ["viral", "video call", "leak", "exposure", "footage", "clip", "upload", "youtube", "social media", "reputation", "private video"]
DIGITAL_ARREST_PATTERNS = ["narcotics", "drugs", "parcel", "fedex", "customs", "seized", "statement", "money laundering", "aadhaar"]
INVESTMENT_PATTERNS = ["invest", "trading", "stock", "market", "crypto", "bitcoin", "returns", "profit", "double", "vip group", "whatsapp group", "guidance", "tips"]

# --- REGEX FOR INTELLIGENCE EXTRACTION ---
REGEX_PATTERNS = {
    "upi": r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}',
    "phone": r'(?:\+91[\-\s]?)?[6-9]\d{9}',
    "link": r'(https?://[^\s]+)|(www\.[^\s]+)',
    "bank_ac": r'[0-9]{9,18}'
}

def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    text = text.lower()
    return [p for p in patterns if p in text]


def extract_intelligence_data(text: str) -> Dict:
    """Extracts UPIs, Links, and Phones using Regex."""
    return {
        "upiIds": re.findall(REGEX_PATTERNS["upi"], text),
        "phoneNumbers": re.findall(REGEX_PATTERNS["phone"], text),
        "phishingLinks": [m[0] or m[1] for m in re.findall(REGEX_PATTERNS["link"], text)],
        "bankAccounts": re.findall(REGEX_PATTERNS["bank_ac"], text)
    }

def detect_scam_signals(message: str) -> Dict:
    if not message:
        return {"confidence": 0, "suspicious_keywords": [], "extracted_data": {}}

    text = message.lower()
    found_signals = []
    
    # Check all categories
    urgency = _match_patterns(text, URGENCY_PATTERNS)
    authority = _match_patterns(text, AUTHORITY_PATTERNS)
    financial = _match_patterns(text, FINANCIAL_PATTERNS)
    threat = _match_patterns(text, THREAT_PATTERNS)
    lottery = _match_patterns(text, LOTTERY_PATTERNS)
    impersonation = _match_patterns(text, IMPERSONATION_PATTERNS)
    job = _match_patterns(text, JOB_PATTERNS)
    utility = _match_patterns(text, UTILITY_PATTERNS)
    digital_arrest = _match_patterns(text, DIGITAL_ARREST_PATTERNS)
    investment = _match_patterns(text, INVESTMENT_PATTERNS)
    sextortion = _match_patterns(text, SEXTORTION_PATTERNS)

    found_signals.extend(urgency + authority + financial + threat + lottery + impersonation + job + utility + digital_arrest + investment + sextortion)
    
    # Calculate Score (Logic from V3.0)
    score = 0
    if authority: score += 30
    if threat: score += 40
    if lottery: score += 50
    if sextortion: score += 50
    
    if digital_arrest:
        score += 40
        if authority or threat: score += 30
            
    if investment:
        score += 30
        if "whatsapp" in text or "telegram" in text or "double" in text: score += 30
            
    if job:
        score += 30
        if "telegram" in text or "daily" in text or "5000" in text: score += 30
    
    if utility:
        if threat: score += 50
        elif urgency and financial: score += 10
    
    if impersonation:
        if financial or urgency: score += 55
        else: score += 10

    if not (utility or job or investment or digital_arrest):
        if financial and urgency: score += 40
        elif financial: score += 20
        elif urgency: score += 10

    unique_keywords = list(set(found_signals))
    if len(unique_keywords) >= 3: score += 10

    # NEW: Extract Hard Data
    extracted_data = extract_intelligence_data(message) # Use original case-sensitive message

    return {
        "confidence": min(score, 100),
        "suspicious_keywords": unique_keywords,
        "extracted_data": extracted_data # Returns UPIs, Links, etc.
    }
