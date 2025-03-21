import re
import logging
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Improved Regex to detect 'http', 'www', and bare domains
URL_PATTERN = re.compile(r"\b(?:https?:\/\/|www\.)[^\s<>\"]+", re.IGNORECASE)

def extract_email_links(email_content):
    """
    Extracts all URLs from an email, handling both plain text and HTML content.
    Returns a dictionary where each URL is an object containing metadata.
    """
    if isinstance(email_content, str):
        email_content = email_content.encode("utf-8")

    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    links = {}  # Dictionary to store link objects

    # Extract text from all parts (plain text and HTML)
    for part in msg.walk():
        body_bytes = part.get_payload(decode=True)
        if body_bytes:
            body_text = body_bytes.decode(part.get_content_charset() or "utf-8", errors="ignore")
            found_links = URL_PATTERN.findall(body_text)  # Extract URLs
            
            for link in found_links:
                link_data = parse_link(link)  # Create link object
                links[link] = link_data  # Store object in dictionary

   # logging.debug(f"Extracted Links: {links}")
    return links

def parse_link(link):
    """
    Parses a URL and returns an object with metadata.
    """
    parsed_url = urlparse(link)

    # Determine if it's HTTP, HTTPS, or just a domain
    protocol = parsed_url.scheme if parsed_url.scheme else "unknown"
    domain = parsed_url.netloc if parsed_url.netloc else link  # Handle bare domains

    return {
        "original": link,
        "protocol": protocol,
        "domain": domain,
        "full_url": link if protocol != "unknown" else f"https://{link}"  # Assume HTTPS if missing
    }