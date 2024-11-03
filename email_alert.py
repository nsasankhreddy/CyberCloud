import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from utils.logger import get_logger

logger = get_logger(__name__)

def send_email_alert(subject, body, recipient_email):
    """Send real-time email alerts using SendGrid."""
    logger.info("Preparing to send email alert...")
    
    message = Mail(
        from_email=os.getenv('SENDER_EMAIL'),
        to_emails=recipient_email,
        subject=subject,
        plain_text_content=body
    )
    try:
        sg = SendGridAPIClient(os.getenv('SENDGRID_API_KEY'))
        response = sg.send(message)
        logger.info(f"Alert sent! Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send alert: {e}")
