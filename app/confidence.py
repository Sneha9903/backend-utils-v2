from pydantic import BaseModel
from typing import List, Optional, Dict

class Message(BaseModel):
    text: str

class ScamRequest(BaseModel):
    sessionId: str
    message: Message
    # Optional: We track history internally, but this allows client to send it too
    conversationHistory: Optional[List[Dict]] = [] 

class ExtractedIntelligence(BaseModel):
    upi_id: Optional[str] = None
    phone_number: Optional[str] = None
    phishing_link: Optional[str] = None
    suspicious_keywords: List[str] = []

class ScamResponse(BaseModel):
    is_scam: bool
    reply: str
    confidence_score: int
    confidence_percentage: str
    extracted_intelligence: ExtractedIntelligence
    explanation: str
