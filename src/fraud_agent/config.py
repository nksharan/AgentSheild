import os

from dotenv import load_dotenv

load_dotenv()

MODEL = os.getenv("MODEL", "google_genai:gemini-3.8-flash")
TEMPERATURE = float(os.getenv("TEMPERATURE", "0"))
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
