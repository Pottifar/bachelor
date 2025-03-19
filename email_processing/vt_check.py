import requests
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Function to read API key from vt_key.txt
def get_api_key(file_path="vt_key.txt"):
    try:
        with open(file_path, "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"API key file '{file_path}' not found. Please create it and add your VirusTotal API key.")

def vt_check_domain(email_content):
    """Check the sender's domain against VirusTotal and retrieve detailed information."""
    
    # Retrieve data to be checked from email
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    # Format domain correctly
    sender_email = parseaddr(msg["From"])[1]
    sender_domain = sender_email.split('@')[-1].lower()
    sender_domain = sender_domain.replace("<", "")
    sender_domain = sender_domain.replace(">", "")
    logging.debug(f"VT CHECK: Extracting sender domain: {sender_domain}")

    # Get API key from file
    API_KEY = get_api_key()

    sender_domain =  "skibidirizz.lol"

    # VirusTotal API URL
    url = f"https://www.virustotal.com/api/v3/domains/{sender_domain}"

    # Headers with API key
    headers = {"x-apikey": API_KEY}

    # Initialize default values (to prevent UnboundLocalError)
    vt_data = {
        "VT-Malicious": 0,
        "VT-Suspicious": 0,
        "VT-Clean": 0,
        "VT-Undetected": 0,
        "VT-Reputation": "Unknown",
        "VT-Category": "Unknown",
        "VT-First-Seen": "Unknown",
        "VT-Last-Analysis": "Unknown",
        "VT-Subdomains": [],
        "VT-Whois-Date": "Not Available",
        "VT-Error": None
    }

    try:
        # Send GET request
        response = requests.get(url, headers=headers)

        # Check response status
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})

            # Extract analysis stats
            analysis = attributes.get("last_analysis_stats", {})
            vt_data["VT-Malicious"] = analysis.get("malicious", 0)
            vt_data["VT-Suspicious"] = analysis.get("suspicious", 0)
            vt_data["VT-Clean"] = analysis.get("harmless", 0)
            vt_data["VT-Undetected"] = analysis.get("undetected", 0)

            # Additional VT metadata
            vt_data["VT-Reputation"] = attributes.get("reputation", "Unknown")
            vt_data["VT-Category"] = ", ".join(attributes.get("categories", {}).values()) if attributes.get("categories") else "Unknown"
            vt_data["VT-Last-Analysis"] = attributes.get("last_analysis_date", "Unknown")
            vt_data["VT-Subdomains"] = attributes.get("subdomains", [])
                                                      
            first_seen_date = attributes.get("creation_date", "Unknown") # Unix time
            vt_data["VT-First-Seen"] = datetime.utcfromtimestamp(first_seen_date).strftime('%Y %d %B') # Datetime conversion

            creation_date = attributes.get("creation_date", "Not Available") # Unix time
            vt_data["Creation-Date"] = datetime.utcfromtimestamp(creation_date).strftime('%Y %d %B') # Datetime conversion

            logging.debug(f"VT CHECK: {vt_data}")

        else:
            vt_data["VT-Error"] = f"Error {response.status_code}: {response.text}"
            logging.error(f"VT CHECK: API error: {vt_data['VT-Error']}")

    except requests.RequestException as e:
        vt_data["VT-Error"] = str(e)
        logging.error(f"VT CHECK: Request error: {vt_data['VT-Error']}")

    return vt_data
