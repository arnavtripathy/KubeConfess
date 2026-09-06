import os

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://api.anthropic.com/v1")
MODEL_NAME = os.environ.get("MODEL_NAME", "claude-haiku-4-5")
MAX_TOKENS = os.environ.get("MAX_TOKENS", 4096)
