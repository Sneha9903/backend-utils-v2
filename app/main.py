from fastapi import FastAPI, Depends, BackgroundTasks
from typing import Dict
from app.schemas import ScamRequest, ScamResponse, ExtractedIntelligence
from app.auth import verify_api_key
from app.extractor import extract_upi_id, extract_phone_number, extract_phishing_link
from app.detector import detect_scam_signals
from app.agent import generate_agent_reply
from app.callback import send_final_callback

app = FastAPI(title="Agentic Scam Honeypot API")

# In-memory storage (Resets on restart)
SESSION_STORE: Dict[str, Dict] = {}

def get_session(session_id: str) -> Dict:
    if session_id not in SESSION_STORE:
        SESSION_STORE[session_id] = {
            "history": [],
            "risk_score": 0,
            "extracted": {"upi_id": None, "phone_number": None, "phishing_link": None},
            "suspicious_keywords": set(), 
            "turns": 0
        }
    return SESSION_STORE[session_id]

@app.post("/analyze-scam", response_model=ScamResponse)
def analyze_scam(
    request: ScamRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    session_id = request.sessionId
    # Access text correctly from the new schema structure
    text = request.message.text
    session = get_session(session_id)
    
    # 1. Update History & Turns
    session["history"].append(text)
    session["turns"] += 1

    # 2. Extraction (Update only if found)
    new_upi = extract_upi_id(text)
    new_phone = extract_phone_number(text)
    new_link = extract_phishing_link(text)

    if new_upi: session["extracted"]["upi_id"] = new_upi
    if new_phone: session["extracted"]["phone_number"] = new_phone
    if new_link: session["extracted"]["phishing_link"] = new_link

    # 3. Detection
    detection = detect_scam_signals(text)
    current_confidence = detection["confidence"]
    keywords = detection["suspicious_keywords"]
    
    session["suspicious_keywords"].update(keywords)
    
    intel_boost = 0
    # BOOST THESE VALUES:
    if session["extracted"]["upi_id"]: intel_boost += 50       
    if session["extracted"]["phishing_link"]: intel_boost += 50 
    
    session["risk_score"] = max(session["risk_score"], current_confidence + intel_boost)
    final_score = min(session["risk_score"], 100)
    is_scam = final_score > 60

    # 4. Generate Agent Reply
    agent_reply = generate_agent_reply(session, text)

    # 5. Handle Callback Trigger (MANDATORY)
    # Trigger if: High Confidence AND (We have Intel OR Conversation is getting long)
    has_intel = session["extracted"]["upi_id"] or session["extracted"]["phishing_link"]
    
    # Only trigger callback if we haven't 'finished' this session yet or if new intel arrived
    if is_scam and (has_intel or session["turns"] >= 5):
        background_tasks.add_task(
            send_final_callback, 
            session_id, 
            is_scam, 
            session["turns"], 
            {
                **session["extracted"], 
                "suspicious_keywords": list(session["suspicious_keywords"])
            }
        )

    # 6. Construct Response (STRICT FORMAT)
    return ScamResponse(
        status="success",  # Required by Hackathon
        reply=agent_reply, # Required by Hackathon
        is_scam=is_scam,
        confidence_score=final_score,
        confidence_percentage=f"{final_score}%",
        extracted_intelligence=ExtractedIntelligence(
            upi_id=session["extracted"]["upi_id"],
            phone_number=session["extracted"]["phone_number"],
            phishing_link=session["extracted"]["phishing_link"],
            suspicious_keywords=list(session["suspicious_keywords"])
        ),
        explanation=f"Risk score {final_score}% based on keywords: {list(keywords)}"
    )