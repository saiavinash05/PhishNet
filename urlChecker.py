from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# List of known malicious domains (for demonstration purposes)
MALICIOUS_DOMAINS = [
    "evil.com",
    "phishing-site.com",
    "malware-domain.com",
]

# Function to check if a domain is malicious
def is_malicious_domain(domain):
    return domain in MALICIOUS_DOMAINS

# Analyze the URL
def analyze_url(url):
    try:
        # Extract domain from URL
        domain = re.search(r"(?:https?:\/\/)?(?:www\.)?([^\/\?:]+)", url).group(1)

        # Check if the domain is malicious
        if is_malicious_domain(domain):
            return "malicious"

        # If no issues are found, the URL is safe
        return "safe"
    except Exception as e:
        print(f"Error analyzing URL: {e}")
        return "safe"  # Assume URL is safe if an error occurs

# Endpoint to analyze URLs
@app.route('/analyze-url', methods=['POST'])
def analyze_url_endpoint():
    data = request.json
    url = data.get('url')
    print(f"Received URL for analysis: {url}")

    # Analyze the URL
    result = analyze_url(url)

    # Return the result
    return jsonify({"status": result, "url": url})

# Start the Flask app
if __name__ == '__main__':
    app.run(port=5000)
