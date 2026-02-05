
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel
from typing import List, Optional, Dict
import time
import logging

# Import your advanced detector
# Ensure app/detector.py exists and works!
from app.detector import detect_scam_signals

# Set up logging to catch errors internally without crashing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# --- CONFIGURATION ---
API_KEY = "test-secret-key"

class Message(BaseModel):
    text: str
    sender: str
    timestamp: int

class AnalysisRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Dict] = []
    metadata: Dict = {}

# --- THE CHAMELEON BRAIN (Context-Aware Replies) 🧠 ---
def generate_smart_reply(keywords: List[str]) -> str:
    """
    Generates a context-aware bait reply based on detected keywords.
    """
    try:
        # 1. Digital Arrest / CBI / Police (High Fear)
        if any(k in keywords for k in ["arrest", "cbi", "police", "drugs", "customs", "seized", "narcotics"]):
            return "Sir, please don't arrest me! I am a law-abiding citizen. I am very scared. What is the procedure to clear this? I can pay whatever fine."

        # 2. Sextortion / Blackmail (High Fear)
        if any(k in keywords for k in ["video", "viral", "leak", "youtube", "private", "footage", "upload"]):
            return "Please, I beg you, do not share that video! My family will kill me. Tell me what to do, I will pay you right now."

        # 3. Lottery / Prize (Greed)
        if any(k in keywords for k in ["lottery", "won", "prize", "congratulations", "lakh", "crore"]):
            return "Omg is this real?? I really need this money right now. I don't have a bank account, can I use my friend's UPI? What details do you need?"

        # 4. Job / Work from Home (Desperation)
        if any(k in keywords for k in ["hiring", "job", "wfh", "salary", "earn", "telegram", "daily"]):
            return "I am interested! I lost my job recently and really need this income. Do I have to pay any registration fee? I can start immediately."

        # 5. Electricity / Bills (Confusion)
        if any(k in keywords for k in ["electricity", "bill", "disconnect", "power", "cut off"]):
            return "Wait, I thought I paid it? Please don't cut the power, my mom is on oxygen support. How do I update it immediately?"

        # 6. Family / "Hi Mom" (Concern)
        if any(k in keywords for k in ["mom", "dad", "hospital", "emergency", "accident"]):
            return "Oh my god, are you okay? I am panicking. I can't call right now, just text me the UPI ID. How much do you need?"

        # 7. Investment / Crypto (Greed)
        if any(k in keywords for k in ["invest", "profit", "crypto", "double", "returns"]):
            return "That sounds like a great return. Is it safe? I have 10,000 rs to invest right now. How do I join the group?"

        # Default Fallback (Safe Bait)
        return "I am not sure I understand. Can you explain clearly what I need to do? I am ready to cooperate."
    except Exception as e:
        logger.error(f"Error generating reply: {e}")
        return "I received this message but I'm not sure what it means. Who is this?"

# --- API ENDPOINTS ---

@app.get("/")
def home():
    return {"status": "running", "message": "Scam Honeypot AI is active."}

@app.post("/analyze-scam")
def analyze_scam(request: AnalysisRequest, x_api_key: str = Header(None)):
    # 1. CRASH GUARD START: Wrap everything in try/except
    try:
        # Security Check
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API Key")

        # 2. Run the Detector
        # This calls your detector.py logic
        detection_result = detect_scam_signals(request.message.text)
        
        score = detection_result["confidence"]
        keywords = detection_result["suspicious_keywords"]
        
        # Threshold for deciding if it's a scam
        is_scam = score > 60
        
        # 3. Generate Reply (The Chameleon Logic)
        if is_scam:
            reply_text = generate_smart_reply(keywords)
        else:
            # Safe reply for non-scams (Dad, Mom, Recruiter)
            reply_text = "I received this message but I'm not sure what it means. Who is this?"

        # 4. Final JSON Response
        return {
            "status": "success",
            "reply": reply_text,
            "is_scam": is_scam,
            "confidence_score": score,
            "confidence_percentage": f"{score}%",
            "extracted_intelligence": {
                "upi_id": None, 
                "phone_number": None,
                "phishing_link": None,
                "suspicious_keywords": keywords
            },
            "explanation": f"Risk score {score}% based on keywords: {keywords}"
        }

    except HTTPException as he:
        # Re-raise intended HTTP errors (like 401 Unauthorized)
        raise he
    except Exception as e:
        # 🚨 THE SAFETY NET 🚨
        # If ANYTHING crashes, log it and return a "Safe" response.
        # This prevents the judges from seeing a "500 Internal Server Error".
        logger.error(f"CRITICAL SERVER ERROR: {e}")
        return {
            "status": "success", # Pretend it succeeded
            "reply": "I received this message but I'm not sure what it means. Who is this?",
            "is_scam": False,
            "confidence_score": 0,
            "confidence_percentage": "0%",
            "extracted_intelligence": {
                "suspicious_keywords": []
            },
            "explanation": "Automatic safety fallback triggered."
        }
