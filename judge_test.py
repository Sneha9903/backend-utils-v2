import requests
import json
import time

# URL (Localhost for now)
API_URL = "http://127.0.0.1:8000/analyze-scam"
API_KEY = "test-secret-key"

def run_judge_simulation():
    print("👨‍⚖️ STARTING JUDGE SIMULATION...\n")

    # --- STEP 1: The Exact Payload from Hackathon PDF ---
    payload = {
        "sessionId": "judge-session-12345",
        "message": {
            "sender": "scammer",
            "text": "Your bank account will be blocked today. Verify immediately. Click https://fake-bank.com",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        
        # --- STEP 2: Verify Response Status ---
        if response.status_code == 200:
            data = response.json()  # <--- 'data' is defined here
            
            print(f"✅ API Status: {response.status_code}")
            
            # Check Mandatory Fields
            if data.get("status") == "success":
                print("✅ Field 'status': success (PASSED)")
            else:
                print(f"❌ Field 'status': {data.get('status')} (FAILED)")

            if data.get("reply"):
                print(f"✅ Field 'reply': \"{data['reply']}\" (PASSED)")
            else:
                print("❌ Field 'reply' is missing! (FAILED)")

            # Check Extra Credit Fields
            print(f"\n📊 Extra Data (For Judges to see):")
            print(f"   - Risk Score: {data.get('confidence_percentage')}")
            
            # --- SHOW THE RAW JSON (Fixed Location) ---
            print("\n📜 RAW JSON RESPONSE (What the Judge Sees):")
            print("---------------------------------------------------")
            print(json.dumps(data, indent=4)) 
            print("---------------------------------------------------")

        else:
            print(f"❌ Critical Error: {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    run_judge_simulation()