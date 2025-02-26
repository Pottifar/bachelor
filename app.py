from flask import Flask, request, render_template, jsonify
from email_processing import headers

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/sender_verification', methods=['POST'])
def api_sender_verification():
    """API endpoint to return parsed email headers as JSON."""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_content = file.read()

    # Parse email headers
    parsed_headers = headers.parse_email_headers(file_content)

    return jsonify(parsed_headers)

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
    parsed_headers = headers.parse_email_headers(file_content)

    return render_template('analyze.html', raw_email=file_content.decode('utf-8'), headers=parsed_headers)

if __name__ == '__main__':
    app.run(debug=True)
