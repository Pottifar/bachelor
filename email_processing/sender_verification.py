from email import policy
from email.parser import BytesParser
import spf
from email.utils import parseaddr
import re
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def verify_sender(email_content):
    """Extract email headers from raw email content and include SPF check."""
    msg = BytesParser(policy=policy.default).parsebytes(email_content)

    headers = {
        "From": parseaddr(msg["From"])[1],  # Extracts only the email address
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Date": msg["Date"],
        "Reply-To": msg["Reply-To"] if "Reply-To" in msg else None,
    }

    # Perform SPF check and append results
    spf_result, spf_explanation, spf_domain, sender_ip = spf_check(email_content)
    headers["SPF-Result"] = spf_result
    headers["SPF-Explanation"] = spf_explanation
    headers["SPF-Domain"] = spf_domain
    headers["SPF-IP"] = sender_ip

    return headers

def extract_sender_ip(received_headers, sender_email):
    """
    Extracts the correct sender IP from 'Received' headers by matching the sender's domain.
    Falls back to the parent domain if the exact match is not found.

    :param received_headers: List of 'Received' headers.
    :param sender_email: The sender's email address (extracted from 'From' header).
    :return: The correct sender IP or None.
    """
    sender_domain = sender_email.split('@')[-1].lower()  # Extract domain from email
    parent_domain = ".".join(sender_domain.split('.')[-2:])  # Extract parent domain as backup
    trusted_ip = None

    logging.debug(f"Extracting sender IP for domain: {sender_domain}")
    logging.debug(f"Parent domain for fallback: {parent_domain}")
    logging.debug(f"Received Headers ({len(received_headers)} found):")

    for header in received_headers:
        logging.debug(header)

    # Try exact domain match first
    for header in received_headers:
        match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)  # Extract IP
        if match:
            ip = match.group(1)

            # Log potential candidate IPs
            logging.debug(f"Found IP in Received header: {ip}")

            # Check if the header mentions the exact sender domain
            if sender_domain in header.lower():
                trusted_ip = ip
                logging.debug(f"Selected IP: {trusted_ip} (matched sender domain)")
                return trusted_ip  # Stop once we find an exact match

    # If no exact match is found, try the parent domain
    for header in received_headers:
        match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
        if match:
            ip = match.group(1)

            if parent_domain in header.lower():
                trusted_ip = ip
                logging.debug(f"Selected IP: {trusted_ip} (matched parent domain)")
                return trusted_ip

    # If still no match, fallback to the first external IP
    for header in received_headers:
        match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
        if match:
            ip = match.group(1)
            trusted_ip = ip
            logging.debug(f"Selected fallback IP: {trusted_ip} (no domain match)")
            return trusted_ip  # Return the first found external IP

    logging.warning("No matching sender IP found in Received headers!")
    return trusted_ip

def spf_check(email_content):
    """Performs an SPF check by extracting the correct sender IP and domain."""
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    received_headers = msg.get_all("Received", [])

    # Extract sender email correctly
    sender_email = parseaddr(msg["From"])[1]
    sender_domain = sender_email.split('@')[-1].lower()
    logging.debug(f"Extracted Sender Email: {sender_email}")

    # Get the correct sender IP
    sender_ip = extract_sender_ip(received_headers, sender_email)

    if not sender_ip or not sender_email:
        logging.error(f"SPF Check Failed - Missing IP ({sender_ip}) or Email ({sender_email})")
        return "unknown", "Missing sender IP or email.", sender_domain

    # Perform SPF check
    try:
        logging.info(f"Performing SPF check for IP: {sender_ip} and Email: {sender_email}")
        result, explanation = spf.check2(sender_ip, sender_email, "unknown")
        logging.info(f"SPF Result: {result} - {explanation}")
        return result, explanation, sender_domain, sender_ip
    except Exception as e:
        logging.error(f"SPF Check Error: {str(e)}", exc_info=True)
        return "error", f"SPF lookup failed: {str(e)}", sender_domain


def dkim_check():
    pass

def dmarc_check():
    pass
