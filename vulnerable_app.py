
import os
import requests
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# This is the endpoint for the local Ollama server
OLLAMA_URL = "http://localhost:11434/api/chat"

@app.route('/chat', methods=['POST'])
def chat():
    """
    This endpoint receives a prompt and forwards it to the Ollama model.
    It's intentionally simple to be a good test target.
    """
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "Prompt not provided"}), 400

    user_prompt = data['prompt']

    # Construct the request to the local Ollama model
    ollama_payload = {
        "model": "gemma:2b",
        "messages": [
            {
                "role": "user",
                "content": user_prompt
            }
        ],
        "stream": False # We want the full response at once
    }

    try:
        response = requests.post(OLLAMA_URL, json=ollama_payload, timeout=10)
        response.raise_for_status() # Raise an exception for bad status codes

        # Extract the content from the Ollama response
        response_data = response.json()
        content = response_data.get('message', {}).get('content', 'No content found.')

        # Return the raw content to the user (or PITT)
        return jsonify({"response": content})

    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500
    except KeyError:
        return jsonify({"error": "Invalid response structure from Ollama"}), 500

if __name__ == '__main__':
    # Runs on http://localhost:8080 (localhost only for security)
    app.run(host='127.0.0.1', port=8080)
