import requests

GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"


def send_final_callback(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    extracted: dict
):
    payload = {
        "sessionId": session_id,
        "scamDetected": scam_detected,
        "totalMessagesExchanged": total_messages,
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [extracted.get("upi_id")] if extracted.get("upi_id") else [],
            "phishingLinks": [extracted.get("phishing_link")] if extracted.get("phishing_link") else [],
            "phoneNumbers": [extracted.get("phone_number")] if extracted.get("phone_number") else [],
            "suspiciousKeywords": extracted.get("suspicious_keywords", [])
        },
        "agentNotes": "Scammer used urgency and payment redirection tactics"
    }

    try:
        requests.post(GUVI_CALLBACK_URL, json=payload, timeout=5)
    except Exception as e:
        print("Callback failed:", e)
