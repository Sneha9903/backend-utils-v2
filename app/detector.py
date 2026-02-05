from typing import Dict, List

# --- 1. EXPANDED PATTERN LISTS ---
URGENCY_PATTERNS = [
    "urgent", "immediately", "now", "today", "within 24 hours", 
    "expire", "blocked", "verify", "kyc", "suspended", "action required"
]

AUTHORITY_PATTERNS = [
    "police", "court", "rbi", "income tax", "manager", "official",
    "customs", "cbi", "officer", "bank manager"
]

FINANCIAL_PATTERNS = [
    "pay", "upi", "amount", "transfer", "refund", "deposit", "fee",
    "bank", "account", "credit", "debit", "wallet", "password", "pin",
    "details", "balance"
]

THREAT_PATTERNS = [
    "jail", "arrest", "suspend", "disconnect", "illegal", "case file",
    "warrant", "legal action", "fir"
]

# NEW: Catches "You won 25 Lakhs" style scams
LOTTERY_PATTERNS = [
    "lottery", "won", "prize", "congratulations", "claim", 
    "winner", "lucky", "cash reward", "crore", "lakh"
]


def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    """Helper function to find keywords in text safely."""
    text = text.lower()
    return [p for p in patterns if p in text]


def detect_scam_signals(message: str) -> Dict:
    """
    Analyzes the message for scam keywords and calculates a risk score.
    Returns a dictionary compatible with main.py.
    """
    # 1. Safety Check: Handle empty messages
    if not message:
        return {"confidence": 0, "suspicious_keywords": []}

    text = message.lower()
    found_signals = []
    
    # 2. Check all categories
    urgency = _match_patterns(text, URGENCY_PATTERNS)
    authority = _match_patterns(text, AUTHORITY_PATTERNS)
    financial = _match_patterns(text, FINANCIAL_PATTERNS)
    threat = _match_patterns(text, THREAT_PATTERNS)
    lottery = _match_patterns(text, LOTTERY_PATTERNS)  # New check

    # Combine all found words
    found_signals.extend(urgency + authority + financial + threat + lottery)
    
    # 3. Enhanced Score Calculation
    score = 0
    if urgency: score += 20
    if authority: score += 30
    if financial: score += 20
    if threat: score += 40      # Threats are very high risk
    if lottery: score += 40     # Lotteries are almost always scams

    # 4. Keyword Multiplier (More keywords = Higher confidence)
    # If we found 3+ unique keywords, boost the score
    unique_keywords = list(set(found_signals))
    if len(unique_keywords) >= 3:
        score += 15

    # 5. Return exactly what main.py expects
    return {
        "confidence": min(score, 100),  # Cap at 100%
        "suspicious_keywords": unique_keywords
    }
