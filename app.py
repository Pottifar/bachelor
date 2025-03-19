from flask import Flask, request, render_template
from email_processing import sender_verification
from email_processing.raw import get_email_body
from email_processing.sense_of_urgency import (detect_urgency, get_urgency_words)
from email_processing.username_check import (detect_generic_username)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_email():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    file_content = file.read()

    # Parse email content with headers 
    parsed_headers = sender_verification.verify_sender(file_content)

    # Hent e-postens brødtekst (både text/plain og text/html)
    body_text = get_email_body(file_content)

    # Sense of urgency:
    urgency_score = detect_urgency(body_text)

    found_urgency_words = get_urgency_words(body_text)

    # Generic username check:
    generic_username_detection = detect_generic_username(body_text)

    return render_template(
        'analyze.html',
        raw_email=file_content.decode('utf-8', errors='ignore'),
        headers=parsed_headers,
        urgency_score=urgency_score,
        email_body=body_text,
        urgency_found=found_urgency_words,
        generic_username_detection=generic_username_detection
    )

if __name__ == '__main__':
    app.run(debug=True)
