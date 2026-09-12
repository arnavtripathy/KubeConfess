import os

# kubeconfess.agent builds an OpenAI client at import time, which requires a
# credential. Provide a dummy one so tests can import the module offline; no
# test makes a real API call (the client is patched where needed).
os.environ.setdefault("API_KEY", "test-key")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
