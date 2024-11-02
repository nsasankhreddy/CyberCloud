from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os

def send_email_alert(subject, body, recipient_email):
    """Send real-time email alerts using SendGrid"""
    print("Preparing to send email alert...")
    
    message = Mail(
        from_email=os.getenv('SENDER_EMAIL'),  # Get sender email from environment variable
        to_emails=recipient_email,
        subject=subject,
        plain_text_content=body
    )
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(f"Alert sent! Status code: {response.status_code}")
    except Exception as e:
        print(f"Failed to send alert: {e}")
