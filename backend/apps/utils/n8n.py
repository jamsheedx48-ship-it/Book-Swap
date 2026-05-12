import requests
from django.conf import settings

def send_email_via_n8n(to_email: str, subject: str, html: str):
    payload = {
        "email": to_email,
        "subject": subject,
        "html": html,
    }
    try:
        response = requests.post(settings.N8N_EMAIL_WEBHOOK_URL, json=payload, timeout=5)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[n8n] webhook failed: {e}", flush=True)