from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url')
    print(f"Received URL for analysis: {url}")

    # TODO: 
    result = "safe"  

    return jsonify({"status": result, "url": url})

if __name__ == '__main__':
    app.run(port=5000)
