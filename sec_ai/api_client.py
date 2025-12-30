import os
import requests
import json
import time
try:
    from sec_ai.prompts import SYSTEM_PROMPT
except ImportError:
    from prompts import SYSTEM_PROMPT

class OpenRouterClient:
    def __init__(self, api_key, model, site_url=None, site_name=None):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://openrouter.ai/api/v1"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": site_url or "https://github.com/vapt-automation", # Construct valid optional headers
            "X-Title": site_name or "Vṛthā VAPT Framework",
        }

    def chat_completion(self, user_prompt, system_prompt=SYSTEM_PROMPT, temp=0.1):
        """
        Sends a chat completion request to OpenRouter.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temp,
            "max_tokens": 4096,
            "top_p": 0.9
        }

        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                return data['choices'][0]['message']['content']
            else:
                return f"Error: Unexpected API response format: {data}"
                
        except requests.exceptions.RequestException as e:
            # Handle API errors gracefully
            if hasattr(e, 'response') and e.response:
                return f"API Error ({e.response.status_code}): {e.response.text}"
            return f"Connection Error: {str(e)}"
        except Exception as e:
            return f"Unexpected Error: {str(e)}"

    def check_connection(self, prompt="Test"):
        """
        Simple check to verify API connectivity.
        """
        response = self.chat_completion(prompt, system_prompt="You are a helpful assistant. Reply briefly.", temp=0.1)
        return response
