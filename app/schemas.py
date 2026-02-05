from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

# --- REQUEST SCHEMA (MATCHING HACKATHON DOC) ---
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class ScamRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    # Added metadata to prevent 422 errors when judges send it
    metadata: Optional[Dict[str, Any]] = None

# --- RESPONSE SCHEMA ---
class ExtractedIntelligence(BaseModel):
    upi_id: Optional[str] = None
    phone_number: Optional[str] = None
    phishing_link: Optional[str] = None
    suspicious_keywords: List[str] = []

class ScamResponse(BaseModel):
    status: str  # REQUIRED by Hackathon doc ("success")
    reply: str   # REQUIRED by Hackathon doc
    is_scam: bool
    confidence_score: int
    confidence_percentage: str
    extracted_intelligence: ExtractedIntelligence
    explanation: str