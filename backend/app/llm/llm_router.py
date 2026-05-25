"""
LLM Router — Multi-provider fallback for code generation.

Priority order:
1. Google Gemini (GEMINI_API_KEY)
2. NVIDIA NIM (NVIDIA_API_KEY)
3. OpenRouter (OPENROUTER_API_KEY)
4. HuggingFace Inference (HUGGINGFACE_API_KEY — optional, works without key too)

Falls through to the next provider if the current one fails.
"""

import os
import time
import logging
import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class LLMProvider:
    """Base class for LLM providers."""

    name: str = "base"

    def is_available(self) -> bool:
        return False

    def generate(self, prompt: str) -> str:
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    """Google Gemini via google-genai SDK."""

    name = "gemini"

    def __init__(self, model=None):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        from google import genai

        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model=self.model,
            contents=prompt,
        )
        return response.text


class GeminiFlashProvider(LLMProvider):
    """Google Gemini 1.5 Flash — separate quota from 2.0."""

    name = "gemini-1.5-flash"

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = "gemini-1.5-flash"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        from google import genai

        client = genai.Client(api_key=self.api_key)
        response = client.models.generate_content(
            model=self.model,
            contents=prompt,
        )
        return response.text


class NvidiaProvider(LLMProvider):
    """NVIDIA NIM API — OpenAI-compatible endpoint."""

    name = "nvidia"

    def __init__(self):
        self.api_key = os.getenv("NVIDIA_API_KEY", "")
        self.model = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-8b-instruct")
        self.base_url = "https://integrate.api.nvidia.com/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        if response.status_code != 200:
            raise Exception(f"NVIDIA API error {response.status_code}: {response.text[:300]}")
        return response.json()["choices"][0]["message"]["content"]


class OpenRouterProvider(LLMProvider):
    """OpenRouter API — free models available."""

    name = "openrouter"

    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
        self.base_url = "https://openrouter.ai/api/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:3000",
            "X-Title": "AI Vulnerability Remediator",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=120,
        )
        if response.status_code != 200:
            raise Exception(f"OpenRouter API error {response.status_code}: {response.text[:300]}")
        return response.json()["choices"][0]["message"]["content"]


class HuggingFaceProvider(LLMProvider):
    """
    HuggingFace Inference API.
    Works WITH or WITHOUT an API key (free tier has rate limits).
    Uses free serverless inference endpoint.
    
    No key: limited rate, may queue.
    With key (free): higher limits.
    Get free key at: https://huggingface.co/settings/tokens
    """

    name = "huggingface"

    def __init__(self):
        self.api_key = os.getenv("HUGGINGFACE_API_KEY", "")
        self.model = os.getenv(
            "HUGGINGFACE_MODEL",
            "Qwen/Qwen2.5-Coder-7B-Instruct"
        )

    def is_available(self) -> bool:
        # Requires a free API key from https://huggingface.co/settings/tokens
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        url = f"https://api-inference.huggingface.co/models/{self.model}/v1/chat/completions"

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a senior security engineer. Return ONLY fixed code. No explanations, no markdown fences."
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
        }

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=180,
        )

        if response.status_code == 503:
            # Model is loading — wait and retry
            raise Exception("HuggingFace model loading (503), will retry")

        if response.status_code != 200:
            raise Exception(
                f"HuggingFace API error {response.status_code}: {response.text[:300]}"
            )

        data = response.json()
        return data["choices"][0]["message"]["content"]


class GroqProvider(LLMProvider):
    """
    Groq API — extremely fast inference, generous free tier.
    Free: 30 req/min, 14400 req/day on llama models.
    Get free key at: https://console.groq.com/keys
    """

    name = "groq"

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        self.base_url = "https://api.groq.com/openai/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 4096,
        }
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=60,
        )
        if response.status_code != 200:
            raise Exception(f"Groq API error {response.status_code}: {response.text[:300]}")
        return response.json()["choices"][0]["message"]["content"]


class LLMRouter:
    """
    Routes LLM requests through multiple providers with automatic fallback.
    Tries each provider in priority order until one succeeds.
    """

    def __init__(self):
        self.providers = [
            GeminiProvider(),
            GeminiFlashProvider(),  # Different model = separate quota
            GroqProvider(),
            NvidiaProvider(),
            OpenRouterProvider(),
            HuggingFaceProvider(),
        ]

        available = [p.name for p in self.providers if p.is_available()]
        logger.info(f"LLM Router initialized. Available providers: {available}")

    def generate(self, prompt: str, max_retries: int = 2) -> tuple[str, str]:
        """
        Generate text using the first available provider.
        Falls through to next provider on failure.

        Returns: (generated_text, provider_name)
        """
        errors = []

        for provider in self.providers:
            if not provider.is_available():
                logger.debug(f"Skipping {provider.name} (not configured)")
                continue

            for attempt in range(1, max_retries + 1):
                try:
                    logger.info(
                        f"Trying {provider.name} (attempt {attempt}/{max_retries})..."
                    )
                    result = provider.generate(prompt)

                    if not result or not result.strip():
                        raise Exception("Empty response from provider")

                    logger.info(f"{provider.name} succeeded ({len(result)} chars)")
                    return result, provider.name

                except Exception as e:
                    error_msg = str(e)
                    logger.warning(
                        f"{provider.name} attempt {attempt} failed: {error_msg[:200]}"
                    )
                    errors.append(f"{provider.name}: {error_msg[:100]}")

                    # Check if transient error worth retrying
                    is_transient = any(
                        code in error_msg
                        for code in [
                            "429", "503", "UNAVAILABLE",
                            "RESOURCE_EXHAUSTED", "rate_limit",
                            "overloaded", "timeout",
                        ]
                    )

                    if attempt < max_retries and is_transient:
                        wait_time = 3 * attempt
                        logger.info(f"Retrying {provider.name} in {wait_time}s...")
                        time.sleep(wait_time)
                    else:
                        # Move to next provider
                        logger.info(f"Moving to next provider after {provider.name} failure")
                        break

        # All providers failed
        error_summary = "; ".join(errors)
        raise Exception(
            f"All LLM providers failed. Errors: {error_summary}"
        )

    def get_status(self) -> dict:
        """Get the status of all configured providers."""
        status = {}
        for provider in self.providers:
            status[provider.name] = {
                "configured": provider.is_available(),
            }
        return status


# Singleton instance
router = LLMRouter()
