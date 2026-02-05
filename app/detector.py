
from typing import Dict, List

# --- 1. PATTERN LISTS (The Complete Hackathon Arsenal) ---

URGENCY_PATTERNS = [
    "urgent", "immediately", "now", "today", "within 24 hours", 
    "expire", "blocked", "verify", "kyc", "suspended", "action required",
    "deadline", "alert", "final notice"
]

# FIX: Removed generic "manager" to prevent false positives in job offers
AUTHORITY_PATTERNS = [
    "police", "court", "rbi", "income tax", "official",
    "cbi", "officer", "bank manager", "cyber cell", "enforcement", "judge"
]

FINANCIAL_PATTERNS = [
    "pay", "upi", "amount", "transfer", "refund", "deposit", "fee",
    "bank", "account", "credit", "debit", "wallet", "pin",
    "details", "balance", "money", "cash", "loan"
]

THREAT_PATTERNS = [
    "jail", "arrest", "suspend", "disconnect", "illegal", "case file",
    "warrant", "legal action", "fir", "fine", "penalty", "block", "cut off",
    "detain", "prosecute"
]

LOTTERY_PATTERNS = [
    "lottery", "won", "prize", "congratulations", "claim", 
    "winner", "lucky", "cash reward", "crore", "lakh", "jackpot"
]

IMPERSONATION_PATTERNS = [
    "mom", "dad", "son", "daughter", "accident", "hospital", 
    "lost phone", "new number", "emergency", "help", "friend", "family"
]

JOB_PATTERNS = [
    "hiring", "part time", "part-time", "wfh", "work from home", 
    "salary", "daily income", "earn", "telegram", "hr", 
    "vacancy", "job offer"
]

UTILITY_PATTERNS = [
    "electricity", "power", "bill", "consumer number", "light", 
    "connection", "meter", "update"
]

# NEW: Sextortion / Blackmail Patterns (The final missing piece)
SEXTORTION_PATTERNS = [
    "viral", "video call", "leak", "exposure", "footage", "clip", 
    "upload", "youtube", "social media", "reputation", "private video"
]

# Specific triggers for "Digital Arrest" / FedEx Scams
DIGITAL_ARREST_PATTERNS = [
    "narcotics", "drugs", "parcel", "fedex", "customs", "seized", 
    "statement", "money laundering", "aadhaar"
]

INVESTMENT_PATTERNS = [
    "invest", "trading", "stock", "market", "crypto", "bitcoin", 
    "returns", "profit", "double", "vip group", "whatsapp group", 
    "guidance", "tips"
]

def _match_patterns(text: str, patterns: List[str]) -> List[str]:
    text = text.lower()
    return [p for p in patterns if p in text]

def detect_scam_signals(message: str) -> Dict:
    if not message:
        return {"confidence": 0, "suspicious_keywords": []}

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

    found_signals.extend(urgency + authority + financial + threat + 
                        lottery + impersonation + job + utility + 
                        digital_arrest + investment + sextortion)
    
    score = 0
    
    # --- SCORING LOGIC ---

    # 1. Critical Threats (Instant High Score)
    if authority: score += 30
    if threat: score += 40
    if lottery: score += 50
    if sextortion: score += 50  # NEW: Blackmail is always high risk
    
    # 2. DIGITAL ARREST LOGIC
    if digital_arrest:
        score += 40
        if authority or threat: 
            score += 30
            
    # 3. INVESTMENT SCAM LOGIC
    if investment:
        score += 30
        if "whatsapp" in text or "telegram" in text or "double" in text:
            score += 30
            
    # 4. JOB SCAM LOGIC (Balanced)
    if job:
        score += 30
        # Only add bonus if it looks like a scam (Telegram/Daily Income)
        if "telegram" in text or "daily" in text or "5000" in text:
            score += 30
    
    # 5. UTILITY / BILL LOGIC (Dad Protection)
    if utility:
        if threat: 
            score += 50  # Threat = SCAM
        elif urgency and financial: 
            score += 10  # Pay today = SAFE (Low Score)
    
    # 6. IMPERSONATION LOGIC ("Hi Mom")
    if impersonation:
        if financial or urgency:
            score += 55  # Mom + Money = SCAM
        else:
            score += 10  # Just chatting = SAFE

    # 7. GENERIC FINANCIAL FALLBACK
    # (Skip if we already identified a specific type to avoid double counting)
    if not (utility or job or investment or digital_arrest):
        if financial and urgency:
            score += 40
        elif financial:
            score += 20
        elif urgency:
            score += 10

    # 8. Keyword Multiplier
    unique_keywords = list(set(found_signals))
    if len(unique_keywords) >= 3:
        score += 10

    return {
        "confidence": min(score, 100),
        "suspicious_keywords": unique_keywords
    }
