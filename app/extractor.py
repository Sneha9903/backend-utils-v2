import re

def extract_upi_id(text: str):
    # Matches example@upi, 99999@ybl, etc.
    match = re.search(r"[\w\.\-]+@[\w\.\-]+", text)
    return match.group(0) if match else None

def extract_phone_number(text: str):
    # Matches +91-999... or 9999999999 (India specific)
    match = re.search(r"(\+91[\-\s]?)?[6-9]\d{9}", text)
    return match.group(0) if match else None

def extract_phishing_link(text: str):
    # Matches http/https links, avoiding simple text
    match = re.search(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+\S*", text)
    return match.group(0) if match else None