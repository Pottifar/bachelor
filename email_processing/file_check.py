import logging
import hashlib
import os
from email import policy
from email.parser import BytesParser
from io import BytesIO
from email_processing.vt_check import vt_check_file_hash

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# List of suspicious file extensions
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif", ".jar", ".msi", ".com", ".cpl", ".hta", ".ps1"}

def get_file_sha256(file_bytes):
    """Calculate SHA-256 hash of the file content."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()

def extract_attachment_info(email_content):
    """
    Extracts detailed information about all attachments in an EML file.
    
    :param email_content: The full content of the EML file as bytes or string.
    :return: A list of dictionaries with attachment details (filename, extension, suspicious, sha256).
    """
    attachments = []

    # Ensure input is in bytes
    if isinstance(email_content, str):
        email_content = email_content.encode('utf-8')  # Convert to bytes if it's a string

    # Parse the email from a byte stream
    msg = BytesParser(policy=policy.default).parse(BytesIO(email_content))

    # Walk through all parts of the email
    for part in msg.walk():
        content_disposition = part.get_content_disposition()  # inline or attachment
        filename = part.get_filename()  # Extract filename
        file_data = part.get_payload(decode=True)  # Decode file content

        # If it's an actual attachment
        if filename and file_data and content_disposition in ('attachment', 'inline'):
            file_extension = os.path.splitext(filename)[1].lower()  # Extract file extension
            is_suspicious = file_extension in SUSPICIOUS_EXTENSIONS  # Check if the extension is suspicious
            file_hash = get_file_sha256(file_data)  # Compute SHA-256 hash

            attachment_info = {
                "filename": filename,
                "extension": file_extension,
                "suspicious": is_suspicious,
                "sha256": file_hash
            }
            
            attachments.append(attachment_info)
            logger.debug(f"Found attachment: {attachment_info}")

    if not attachments:
        logger.debug("No attachments found")

    return attachments