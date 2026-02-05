def generate_agent_reply(session_data: dict, current_message: str) -> str:
    """
    Decides the next move based on:
    1. Confidence Score (Are we sure it's a scam?)
    2. Missing Intel (Do we have the UPI/Link yet?)
    3. Conversation Depth (How long have we been talking?)
    """
    risk = session_data["risk_score"]
    intel = session_data["extracted"]
    
    # 1. Low Confidence: Play dumb to get more info
    if risk < 30:
        return "I received this message but I'm not sure what it means. Who is this?"

    # 2. Medium Confidence: Stall and feign concern
    if 30 <= risk < 60:
        return "Oh my god, I didn't know this was expired. I am very worried. What should I do now?"

    # 3. High Confidence - BUT missing Intelligence (The Honeypot Logic)
    
    # If we detect a scam but have NO payment link/UPI, bait them for it.
    if not intel.get("upi_id") and not intel.get("phishing_link"):
        return "I am ready to pay the penalty to avoid legal action. Can you send me the UPI ID or payment link?"

    # If we have a Link but no UPI, ask if UPI works (wasting time).
    if intel.get("phishing_link") and not intel.get("upi_id"):
        return "The link isn't opening on my phone. Can I just Google Pay you directly? What is the ID?"

    # 4. Maximum Confidence & Intel Collected: Final stall before 'blocking'
    return "Okay, I am trying to send it now. Please wait a moment while I find my card."