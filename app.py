from flask import Flask, request, render_template, jsonify
import requests

from email_processing.sender_verification import verify_sender
from email_processing.vt_check import vt_check_domain, vt_check_url
from email_processing.raw import get_email_body
from email_processing.sense_of_urgency import detect_urgency, get_urgency_words
from email_processing.username_check import detect_generic_username
from email_processing.link_check import extract_email_links
from email_processing.file_check import extract_attachment_info
from email_processing.vt_check import vt_check_file_hash

app = Flask(__name__)

def get_vt_api_key():
    """Reads the VirusTotal API key from vt_key.txt."""
    try:
        with open("vt_key.txt", "r") as file:
            return file.read().strip()
    except FileNotFoundError:
        print("Error: vt_key.txt not found. Please add your VirusTotal API key.")
        return None

VT_API_KEY = get_vt_api_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    """Render email analysis page."""
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']

    if file.filename == '':
        return "No selected file", 400

    file_content = file.read()

    # Parse email content with headers
    parsed_headers = verify_sender(file_content)

    # VT CHECK
    vt_check_data = vt_check_domain(file_content)

    # Hent e-postens brødtekst (både text/plain og text/html)
    body_text = get_email_body(file_content)

    # Sense of urgency:
    urgency_score = detect_urgency(body_text)

    found_urgency_words = get_urgency_words(body_text)

    # Generic username check:
    generic_username_detection = detect_generic_username(body_text)

    # Check links
    extracted_links = extract_email_links(body_text)

    # Check files
    files = extract_attachment_info(file_content)

    return render_template(
        'analyze.html', raw_email=file_content.decode('utf-8'), 
        headers=parsed_headers, 
        vt_data=vt_check_data,
        urgency_score=urgency_score,
        email_body=body_text,
        urgency_found=found_urgency_words,
        generic_username_detection=generic_username_detection,
        links=extracted_links,
        email_files=files
        )

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.json
    url_to_check = data.get("url")
    
    if not url_to_check:
        return jsonify({"error": "No URL provided"}), 400
    
    result = vt_check_url(url_to_check)
    return jsonify(result)

@app.route('/check_file_hash', methods=['POST'])
def check_file_hash():
    """API endpoint to check a file hash with VirusTotal."""
    data = request.json
    file_hash = data.get("hash")

    if not file_hash:
        return jsonify({"error": "No hash provided"}), 400

    result = vt_check_file_hash(file_hash)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)