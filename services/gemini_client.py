import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

# Gemini Client
gemini_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_KEY"))
