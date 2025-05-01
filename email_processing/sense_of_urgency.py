import re
from email import policy
from email.parser import BytesParser, Parser

URGENCY_WORDS = [
    # Norske ord/uttrykk:
    "haster", "umiddelbart", "nå", "viktig", "haste", "straks",
    "umiddelbar", "umiddelbar handling", "vær rask", "svar umiddelbart",
    "kontakt straks", "snarest", "svar nå", "handling kreves", "reaksjon påkrevd",
    
    # Engelske ord/uttrykk:
    "urgent", "account suspended", "verify now", "act fast", "final warning", "last chance",
    "act immediately", "do not delay", "immediate action", "limited time", "time sensitive",
    "emergency", "rush", "prompt response", "respond now", "critical", "immediate response", "time-critical"
]

def extract_email_body(email_content):
    """
    Extracts and returns only the body content from an email, handling both bytes and string inputs.
    """
    # Ensure the input is in bytes format
    if isinstance(email_content, str):
        email_content = email_content.encode("utf-8")

    # Parse the email
    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    # Extract the email body
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == "text/plain":
                body_bytes = part.get_payload(decode=True)
                if body_bytes:
                    body = body_bytes.decode(part.get_content_charset() or "utf-8", errors="ignore")
                    break  # Stop after extracting the first plain text part
    else:
        body_bytes = msg.get_payload(decode=True)
        if body_bytes:
            body = body_bytes.decode(msg.get_content_charset() or "utf-8", errors="ignore")

    return body

def detect_urgency(email_content):
    """
    Detects urgency words in the email body (ignores headers).
    """
    body_text = extract_email_body(email_content).lower()
    urgency_count = sum(len(re.findall(rf"\b{word}\b", body_text)) for word in URGENCY_WORDS)
    return urgency_count

def get_urgency_words(email_content):
    """
    Returns a list of unique urgency words found in the email body.
    """
    found_words = set()
    body_text = extract_email_body(email_content).lower()

    for word in URGENCY_WORDS:
        pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
        if pattern.search(body_text):
            found_words.add(word)
    
    return list(found_words)