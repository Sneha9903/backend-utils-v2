
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict
import requests
import logging

# Import detector
from app.detector import detect_scam_signals

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# --- CONFIGURATION ---
API_KEY = "test-secret-key"
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

class Message(BaseModel):
    text: str
    sender: str
    timestamp: int

class AnalysisRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Dict] = []
    metadata: Dict = {}

# --- SMART REPLY LOGIC (UNCHANGED) ---
def generate_smart_reply(keywords: List[str]) -> str:
    # ... (Keep your existing bait logic from V3.0 here) ...
    # For brevity, I am pasting the function body you already have
    try:
        if any(k in keywords for k in ["arrest", "cbi", "police", "drugs", "customs", "seized", "narcotics"]):
            return "Sir, please don't arrest me! I am a law-abiding citizen. I am very scared. What is the procedure to clear this? I can pay whatever fine."
        if any(k in keywords for k in ["video", "viral", "leak", "youtube", "private", "footage", "upload"]):
            return "Please, I beg you, do not share that video! My family will kill me. Tell me what to do, I will pay you right now."
        if any(k in keywords for k in ["lottery", "won", "prize", "congratulations", "lakh", "crore"]):
            return "Omg is this real?? I really need this money right now. I don't have a bank account, can I use my friend's UPI? What details do you need?"
        if any(k in keywords for k in ["hiring", "job", "wfh", "salary", "earn", "telegram", "daily"]):
            return "I am interested! I lost my job recently and really need this income. Do I have to pay any registration fee? I can start immediately."
        if any(k in keywords for k in ["electricity", "bill", "disconnect", "power", "cut off"]):
            return "Wait, I thought I paid it? Please don't cut the power, my mom is on oxygen support. How do I update it immediately?"
        if any(k in keywords for k in ["mom", "dad", "hospital", "emergency", "accident"]):
            return "Oh my god, are you okay? I am panicking. I can't call right now, just text me the UPI ID. How much do you need?"
        if any(k in keywords for k in ["invest", "profit", "crypto", "double", "returns"]):
            return "That sounds like a great return. Is it safe? I have 10,000 rs to invest right now. How do I join the group?"
        return "I am not sure I understand. Can you explain clearly what I need to do? I am ready to cooperate."
    except Exception:
        return "I received this message but I'm not sure what it means. Who is this?"

# --- MANDATORY CALLBACK FUNCTION ---
def send_guvi_callback(session_id: str, is_scam: bool, msg_count: int, intelligence: Dict):
    """Sends the mandatory final report to GUVI."""
    try:
        payload = {
            "sessionId": session_id,
            "scamDetected": is_scam,
            "totalMessagesExchanged": msg_count,
            "extractedIntelligence": {
                "bankAccounts": intelligence.get("bankAccounts", []),
                "upiIds": intelligence.get("upiIds", []),
                "phishingLinks": intelligence.get("phishingLinks", []),
                "phoneNumbers": intelligence.get("phoneNumbers", []),
                "suspiciousKeywords": intelligence.get("suspiciousKeywords", [])
            },
            "agentNotes": "Scam intent detected via heuristic engine. Autonomous agent engaged to extract intelligence."
        }
        
        # We use a timeout so it doesn't hang your server
        response = requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
        logger.info(f"GUVI Callback Sent: {response.status_code} | {response.text}")
    except Exception as e:
        logger.error(f"Failed to send GUVI callback: {e}")

@app.post("/analyze-scam")
def analyze_scam(request: AnalysisRequest, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    try:
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="Invalid API Key")

        # 1. Detect
        detection_result = detect_scam_signals(request.message.text)
        score = detection_result["confidence"]
        keywords = detection_result["suspicious_keywords"]
        extracted_data = detection_result["extracted_data"] # Regex results
        
        is_scam = score > 60
        
        # 2. Reply
        if is_scam:
            reply_text = generate_smart_reply(keywords)
        else:
            reply_text = "I received this message but I'm not sure what it means. Who is this?"

        # 3. PREPARE INTELLIGENCE DATA
        intelligence_payload = extracted_data
        intelligence_payload["suspiciousKeywords"] = keywords

        # 4. FIRE CALLBACK (MANDATORY)
        # We send this ONLY if it's a scam.
        # We use BackgroundTasks so we reply to the user immediately, then notify GUVI.
        if is_scam:
            total_msgs = len(request.conversationHistory) + 1
            background_tasks.add_task(
                send_guvi_callback, 
                request.sessionId, 
                True, 
                total_msgs, 
                intelligence_payload
            )

        # 5. Return Response
        return {
            "status": "success",
            "reply": reply_text,
            "is_scam": is_scam,
            "confidence_score": score,
            "confidence_percentage": f"{score}%",
            "extracted_intelligence": {
                "upi_id": extracted_data.get("upiIds"),
                "phone_number": extracted_data.get("phoneNumbers"),
                "phishing_link": extracted_data.get("phishingLinks"),
                "suspicious_keywords": keywords
            },
            "explanation": f"Risk score {score}% based on keywords: {keywords}"
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"CRITICAL ERROR: {e}")
        return {
            "status": "success",
            "reply": "I received this message but I'm not sure what it means. Who is this?",
            "is_scam": False
        }
