import re
import ssl
import socket
import logging
from email import policy
from datetime import datetime
from urllib.parse import urlparse
from email.parser import BytesParser

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Improved Regex to detect 'http', 'www', and bare domains
URL_PATTERN = re.compile(r"\b(?:https?:\/\/|www\.)[^\s<>\"]+", re.IGNORECASE)

def check_ssl_status(domain, port=443):
    """
    Checks whether the SSL certificate for a domain is valid.
    Returns "Valid" if SSL is active and not expired, otherwise returns "Invalid".
    """
    logging.debug(f"Checking SSL status for domain: {domain}, port: {port}")
    
    try:
        # Create a socket and wrap it in an SSL context
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            logging.debug("Socket connection established.")
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                logging.debug("SSL handshake completed.")
                cert = ssock.getpeercert()
                logging.debug("SSL certificate retrieved.")

        # Get certificate expiration date
        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days

        logging.debug(f"Certificate expiry date: {expiry_date}, Days until expiry: {days_remaining}")

        return "Valid" if days_remaining > 0 else "Invalid"

    except ssl.SSLError as e:
        logging.debug(f"SSL error occurred: {e}")
        return "Invalid"
    except socket.error as e:
        logging.debug(f"Socket error occurred: {e}")
        return "Invalid"
    except Exception as e:
        logging.debug(f"Unexpected error occurred: {e}")
        return "Invalid"

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
    https_status = check_ssl_status(domain)

    return {
        "original": link,
        "protocol": protocol,
        "domain": domain,
        "full_url": link if protocol != "unknown" else f"https://{link}",  # Assume HTTPS if missing
        "ssl_status": https_status
    }