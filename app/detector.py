from typing import Dict, List

URGENCY_PATTERNS = ["urgent", "immediately", "now", "today", "within 24 hours", "expire", "blocked"]
AUTHORITY_PATTERNS = ["police", "court", "rbi", "income tax", "manager", "official"]
FINANCIAL_PATTERNS = ["pay", "upi", "amount", "transfer", "refund", "deposit", "fee"]
THREAT_PATTERNS = ["jail", "arrest", "suspend", "disconnect", "illegal", "case file"]

def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    text = text.lower()
    return [p for p in patterns if p in text]

def detect_scam_signals(message: str) -> Dict:
    text = message.lower()
    found_signals = []
    
    # Check all categories
    urgency = _match_patterns(text, URGENCY_PATTERNS)
    authority = _match_patterns(text, AUTHORITY_PATTERNS)
    financial = _match_patterns(text, FINANCIAL_PATTERNS)
    threat = _match_patterns(text, THREAT_PATTERNS)

    found_signals.extend(urgency + authority + financial + threat)
    
    # Base score calculation
    score = 0
    if urgency: score += 20
    if authority: score += 30
    if financial: score += 20
    if threat: score += 30

    # Return exactly what main.py expects
    return {
        "confidence": min(score, 100),
        "suspicious_keywords": list(set(found_signals))  # Remove duplicates
    }