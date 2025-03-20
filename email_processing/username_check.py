import re
import logging
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup  # For extracting visible text from HTML emails

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Generic terms to check
GENERIC_TERMS = [
    "user", "kunde", "customer", "dear user", "dear kunde", "dear customer",
    "valued customer", "client"
]

def extract_email_body(email_content):
    """
    Extracts and returns only the visible text from an email, handling both plain text and HTML.
    Ensures HTML processing happens when no plain text is available.
    """
    if isinstance(email_content, str):
        email_content = email_content.encode("utf-8")

    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    # Initialize body as empty
    body = ""

    # Try to extract plain text first
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            body_bytes = part.get_payload(decode=True)
            if body_bytes:
                body = body_bytes.decode(part.get_content_charset() or "utf-8", errors="ignore")
                break  # Stop after extracting the first plain text part
    
    for part in msg.walk():
        content_type = part.get_content_type()
        html_bytes = part.get_payload(decode=True)
        html_text = html_bytes.decode(part.get_content_charset() or "utf-8", errors="ignore")
        body = extract_visible_text_from_html(html_text)
        break  # Stop after extracting HTML text if no plain text found

    logging.debug(f"Extracted Email Body (Final Cleaned Text):\n{body}\n{'='*40}")
    return body.strip()


def extract_visible_text_from_html(html_content):
    """
    Extracts only the visible text from HTML, removing all tags but keeping their text content.
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # Remove script, style, metadata, and non-visible elements
    for tag in soup(["script", "style", "head", "meta", "title", "noscript", "link"]):
        tag.decompose()  # Completely remove these elements

    # Unwrap elements while keeping their text
    for tag in soup.find_all():
        tag.replace_with_children()  # Remove tag but keep the inner text

    visible_text = soup.get_text(separator=" ", strip=True)

    logging.debug(f"Extracted Visible Text from HTML (Improved):\n{visible_text}\n{'='*40}")
    return visible_text


def detect_generic_username(email_content):
    """
    Analyzes the email **body text** (ignoring headers, HTML tags, and code) for generic usernames.
    
    Returns:
      - count: number of unique generic expressions found
      - terms: a list of detected generic terms
    """
    found_terms = set()
    email_body = extract_email_body(email_content).lower()  # Get only the cleaned body text

    logging.debug(f"Text Being Checked for Generic Terms:\n{email_body}\n{'='*40}")

    for term in GENERIC_TERMS:
        pattern = re.compile(r'\b' + re.escape(term) + r'\b', re.IGNORECASE)
        if pattern.search(email_body):
            found_terms.add(term)
    
    # Check for greetings containing an email address (e.g., "Dear someone@example.com")
    email_pattern = re.compile(r'dear\s+([\w\.-]+@[\w\.-]+)', re.IGNORECASE)
    email_match = email_pattern.search(email_body)
    if email_match:
        found_terms.add(email_match.group(1))
    
    result = {
        "count": len(found_terms),
        "terms": list(found_terms)
    }

    logging.debug(f"Detected Generic Terms: {result}\n{'='*40}")
    return result