import os
import requests
from dotenv import load_dotenv

# Explicitly find and load .env from the project root directory
basedir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
dotenv_path = os.path.join(basedir, '.env')
load_dotenv(dotenv_path)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

def send_telegram_alert(src_ip: str, threat_type: str, mitre_ttp: str, action_taken: str) -> None:
    if not TELEGRAM_BOT_TOKEN:
        print("[-] Error: TELEGRAM_BOT_TOKEN is empty! Check your .env path.")
        return

    message = (
        f"🚨 *SECURITY INCIDENT DETECTED*\n\n"
        f"• *Source IP:* `{src_ip}`\n"
        f"• *Attack Type:* {threat_type}\n"
        f"• *MITRE ATT&CK TTP:* `{mitre_ttp}`\n"
        f"• *SOAR Action:* {action_taken}\n"
        f"• *Status:* 🟢 Automated Mitigation Complete"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            print("SOC Alert dispatched successfully via Webhook.")
        else:
            print(f"Webhook delivery failed: {response.text}")
    except requests.RequestException as e:
        print(f"Error sending Telegram alert: {e}")