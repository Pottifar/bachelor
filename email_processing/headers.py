import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

def parse_email_headers(email_content):
    """Extract email headers from raw email content."""
    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    headers = {
        "From": parseaddr(msg["From"])[1],  # Extracts only the email address
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Date": msg["Date"],
        "Reply-To": msg["Reply-To"] if "Reply-To" in msg else None,
    }

    return headers