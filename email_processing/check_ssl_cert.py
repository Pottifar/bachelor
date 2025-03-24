import ssl
import socket
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def check_ssl_status(domain, port=443):
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

        return {
            "domain": domain,
            "issuer": dict(cert['issuer']),
            "subject": dict(cert['subject']),
            "valid_from": cert['notBefore'],
            "valid_until": cert['notAfter'],
            "days_until_expiry": days_remaining,
            "status": "Valid" if days_remaining > 0 else "Expired"
        }

    except ssl.SSLError as e:
        logging.debug(f"SSL error occurred: {e}")
        return {"domain": domain, "error": f"SSL error: {str(e)}"}
    except socket.error as e:
        logging.debug(f"Socket error occurred: {e}")
        return {"domain": domain, "error": f"Socket error: {str(e)}"}
    except Exception as e:
        logging.debug(f"Unexpected error occurred: {e}")
        return {"domain": domain, "error": f"Unexpected error: {str(e)}"}