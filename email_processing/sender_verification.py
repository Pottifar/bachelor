from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
import spf
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
    spf_result, spf_explanation = spf_check(email_content)
    headers["SPF-Result"] = spf_result
    headers["SPF-Explanation"] = spf_explanation

    return headers

def extract_sender_ip(received_headers, sender_email):
    """
    Extracts the correct sender IP from 'Received' headers by matching the sender's domain.
    Prioritizes the correct SMTP relay (not the first or last hop).
    
    :param received_headers: List of 'Received' headers.
    :param sender_email: The sender's email address (extracted from 'From' header).
    :return: The correct sender IP or None.
    """
    sender_domain = sender_email.split('@')[-1].lower()  # Extract domain from email
    trusted_ip = None

    logging.debug(f"Extracting sender IP for domain: {sender_domain}")
    logging.debug(f"Received Headers ({len(received_headers)} found):")
    for header in received_headers:
        logging.debug(header)

    # Process headers **from newest to oldest**, but **ignore the first and last**
    for index, header in enumerate(received_headers[1:-1], start=1):  # Skip first and last
        match = re.search(r"\[(\d+\.\d+\.\d+\.\d+)\]", header)
        if match:
            ip = match.group(1)
            logging.debug(f"Found IP in Received header #{index}: {ip}")

            # Check if the header mentions the sender's domain
            if sender_domain in header.lower():
                trusted_ip = ip
                logging.debug(f"Selected IP: {trusted_ip} (matched sender domain)")
                break

    if not trusted_ip:
        logging.warning("No matching sender IP found in Received headers!")

    return trusted_ip

def spf_check(email_content):
    """Performs an SPF check by extracting the correct sender IP."""
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    received_headers = msg.get_all("Received", [])

    # Extract sender email correctly
    sender_email = parseaddr(msg["From"])[1]
    logging.debug(f"Extracted Sender Email: {sender_email}")

    # Get the correct sender IP (ignoring the first and last "Received" headers)
    sender_ip = extract_sender_ip(received_headers, sender_email)

    if not sender_ip or not sender_email:
        logging.error(f"SPF Check Failed - Missing IP ({sender_ip}) or Email ({sender_email})")
        return "unknown", "Missing sender IP or email."

    # Perform SPF check
    try:
        logging.info(f"Performing SPF check for IP: {sender_ip} and Email: {sender_email}")
        result, explanation = spf.check2(sender_ip, sender_email, "unknown")
        logging.info(f"SPF Result: {result} - {explanation}")
        return result, explanation
    except Exception as e:
        logging.error(f"SPF Check Error: {str(e)}", exc_info=True)
        return "error", f"SPF lookup failed: {str(e)}"


def dkim_check():
    pass

def dmarc_check():
    pass
