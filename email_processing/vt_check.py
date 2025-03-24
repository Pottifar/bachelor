import requests
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import logging
from datetime import datetime
import time

# Configure # logging
# logging.basicConfig(level=# logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

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
    # logging.debug(f"VT CHECK: Extracting sender domain: {sender_domain}")

    # Get API key from file
    API_KEY = get_api_key()

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
                                                      
            creation_date = attributes.get("creation_date")  # Unix timestamp or None

            if isinstance(creation_date, int):  # Ensure it's an integer before converting
                vt_data["Creation-Date"] = datetime.utcfromtimestamp(creation_date).strftime('%Y %d %B')
            else:
                vt_data["Creation-Date"] = "Unknown"

            # logging.debug(f"VT CHECK: {vt_data}")

        else:
            vt_data["VT-Error"] = f"Error {response.status_code}: {response.text}"
            # logging.error(f"VT CHECK: API error: {vt_data['VT-Error']}")

    except requests.RequestException as e:
        vt_data["VT-Error"] = str(e)
        # logging.error(f"VT CHECK: Request error: {vt_data['VT-Error']}")

    return vt_data

def vt_check_url(url_to_check):

    """Submit a URL to VirusTotal for scanning and retrieve detailed information."""
    
    # Get API key
    API_KEY = get_api_key()
    
    # VirusTotal API URLs
    submit_url = "https://www.virustotal.com/api/v3/urls"
    
    # Headers with API key
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": API_KEY
    }
    
    # Prepare the data payload for URL submission
    payload = {"url": url_to_check}
    
    # logging.debug(f"Submitting URL to VirusTotal: {url_to_check}")
    
    # Submit URL for scanning
    response = requests.post(submit_url, headers=headers, data=payload)
    # logging.debug(f"Response status: {response.status_code}, Response text: {response.text}")
    
    if response.status_code != 200:
        return {"VT-Error": f"Error {response.status_code}: {response.text}"}
    
    data = response.json()
    # logging.debug(f"Submission response data: {data}")
    analysis_link = data.get("data", {}).get("links", {}).get("self")
    if not analysis_link:
        return {"VT-Error": "No analysis link returned"}
    
    # logging.debug(f"Analysis link: {analysis_link}")
    
    # Fetch the report using the analysis link (Wait for scan completion)
    attempts = 0
    max_attempts = 5
    wait_time = 30
    
    while attempts < max_attempts:
        # logging.debug(f"Attempt {attempts + 1}: Fetching analysis report...")
        report_response = requests.get(analysis_link, headers=headers)
        # logging.debug(f"Report response status: {report_response.status_code}, Response text: {report_response.text}")
        
        if report_response.status_code == 200:
            report_data = report_response.json()
            # logging.debug(f"Report response data: {report_data}")
            attributes = report_data.get("data", {}).get("attributes", {})
            status = attributes.get("status")
            
            if status == "completed":
                return {
                    "VT-Malicious": attributes.get("stats", {}).get("malicious", 0),
                    "VT-Suspicious": attributes.get("stats", {}).get("suspicious", 0),
                    "VT-Clean": attributes.get("stats", {}).get("harmless", 0)
                }
        
        time.sleep(wait_time)
        attempts += 1
    
    return {"VT-Error": "Analysis took too long or failed."}

def vt_check_file_hash(file_hash):
    """
    Checks a file's hash (SHA-256) against VirusTotal.

    :param file_hash: The SHA-256 hash of the file.
    :return: A dictionary with VirusTotal scan results.
    """
    api_key = get_api_key()
    if not api_key:
        return {"error": "API key not found"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)

        # Handle 404: File hash not found in VirusTotal
        if response.status_code == 404:
            logging.warning(f"File hash {file_hash} not found in VirusTotal.")
            return {
                "sha256": file_hash,
                "malicious": 0,
                "suspicious": 0,
                "undetected": 0,
                "scan_date": "Unknown",
                "message": "This file has not been seen before",
                "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }

        response.raise_for_status()  # Raise an error for other failed requests
        data = response.json()

        if "data" in data:
            attributes = data["data"]["attributes"]
            results = {
                "sha256": file_hash,
                "malicious": attributes["last_analysis_stats"]["malicious"],
                "suspicious": attributes["last_analysis_stats"]["suspicious"],
                "undetected": attributes["last_analysis_stats"]["undetected"],
                "scan_date": attributes.get("last_analysis_date", "Unknown"),
                "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
            logging.info(f"VirusTotal Results for {file_hash}: {results}")
            return results
        else:
            return {"error": "No results found for this hash"}

    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal API request failed: {e}")
        return {"error": str(e)}