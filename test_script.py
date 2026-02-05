import requests
import json
import time

# Configuration
API_URL = "http://127.0.0.1:8000/analyze-scam"
API_KEY = "test-secret-key"
SESSION_ID = "judge_demo_session_001"

# Headers
headers = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}

def send_message(text):
    print(f"\n🔴 Scammer says: {text}")
    
    # FIX: Added 'sender' and 'timestamp' to match your strict schema
    payload = {
        "sessionId": SESSION_ID,
        "message": {
            "text": text,
            "sender": "scammer",  
            "timestamp": int(time.time())
        },
        "conversationHistory": []
    }
    
    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            print(f"🟢 Agent replies: {data['reply']}")
            print(f"   [Risk Score: {data['confidence_percentage']}]")
            # Handle cases where intelligence might be None
            intel = data.get('extracted_intelligence', {})
            print(f"   [Intel Extracted]: UPI={intel.get('upi_id')}, Link={intel.get('phishing_link')}")
            return data
        else:
            print(f"❌ Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"❌ Connection Failed: {e}")

# --- THE SIMULATION ---
print("--- STARTING SCAM SIMULATION ---")

# Turn 1: Generic opening
send_message("Hello, I am calling from your bank.")
time.sleep(1)

# Turn 2: Urgency + Threat
send_message("Your KYC is expired. We will block your account in 10 minutes if you don't update.")
time.sleep(1)

# Turn 3: The Agent should bait for the link now. Scammer sends link.
send_message("Please click here to update immediately: http://update-kyc-bank.com/login")
time.sleep(1)

# Turn 4: The Agent should stall or ask for UPI. Scammer sends UPI.
send_message("You need to pay a reactivation fee of 10rs to verify. Send to manager@upi")
time.sleep(1)

print("\n--- SIMULATION END ---")
print("Check your terminal running uvicorn. You should see the background task triggering.")