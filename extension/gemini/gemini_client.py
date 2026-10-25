"""Thin wrapper around the Gemini API that turns a repair prompt into a fixed file."""

import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MODEL = "gemini-3.1-pro-preview"
MODEL_ENV_VAR = "VIBECHECK_GEMINI_MODEL"

# 429 = rate limited, 5xx = Google-side problems. Everything else (bad key, bad request) won't fix itself.
RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}
# If Google says to come back later than this, the quota is used up for the day, so stop instead of waiting.
MAX_RETRY_WAIT = 120


class GeminiError(Exception):
    """Gemini could not be called, or its answer can't be used as a fixed file."""


class QuotaExhaustedError(GeminiError):
    """The API key has no quota left for this model. Every further call will fail too."""


@dataclass
class GeminiResult:
    text: str  # fixed file content, markdown fences already removed
    model: str
    finish_reason: str
    usage: dict = field(default_factory=dict)


def strip_code_fences(text: str) -> str:
    """Remove a ```lang ... ``` wrapper if the model added one despite being told not to."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return text

    lines = stripped.splitlines()
    lines = lines[1:]  # drop the opening ```python line
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines)


def load_dotenv(path: Path = Path(__file__).resolve().parent / ".env"):
    """Load KEY=value lines from extension/gemini/.env without overriding variables already set."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and not key.strip().startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _short_error(error: Exception) -> str:
    """One line instead of the full JSON body the SDK puts in str(error)."""
    code = getattr(error, "code", None) or type(error).__name__
    message = (getattr(error, "message", None) or str(error)).strip()
    # Some httpx timeouts have no message at all.
    first_line = message.splitlines()[0] if message else "no details"
    return f"{code}: {first_line[:300]}"


def _retry_delay(error: Exception) -> float | None:
    """Seconds Google asked us to wait (RetryInfo.retryDelay), if it said."""
    for detail in ((getattr(error, "details", None) or {}).get("error", {}).get("details", [])):
        delay = detail.get("retryDelay") if isinstance(detail, dict) else None
        if delay:
            try:
                return float(delay.rstrip("s"))
            except ValueError:
                return None
    return None


def _is_retryable(error: Exception) -> bool:
    if getattr(error, "code", None) in RETRYABLE_STATUS:
        return True
    try:
        import httpx  # installed with google-genai
    except ImportError:
        return False
    return isinstance(error, httpx.TransportError)  # dropped connection, read timeout, ...


class GeminiClient:
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.2,
        max_output_tokens: int = 65536,
        thinking_level: str | None = None,
        timeout: int = 300,
        max_retries: int = 5,
        client=None,
    ):
        """api_key falls back to GEMINI_API_KEY / GOOGLE_API_KEY. `client` lets tests pass a fake."""
        load_dotenv()
        self.model = model or os.environ.get(MODEL_ENV_VAR, DEFAULT_MODEL)
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.thinking_level = thinking_level
        self.max_retries = max_retries

        if client is not None:
            self._client = client
            return

        try:
            from google import genai
            from google.genai import types
        except ImportError:
            raise GeminiError("google-genai is not installed. Run: pip install -r requirements.txt")

        api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise GeminiError("No Gemini API key. Set GEMINI_API_KEY (see .env.example).")

        # The SDK takes the timeout in milliseconds.
        self._client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=timeout * 1000))

    def _config(self):
        from google.genai import types

        config = {
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
        }
        if self.thinking_level:
            config["thinking_config"] = types.ThinkingConfig(thinking_level=self.thinking_level)
        return types.GenerateContentConfig(**config)

    def _call(self, prompt: str):
        """Call Gemini once per attempt, backing off on rate limits and server errors."""
        for attempt in range(self.max_retries + 1):
            try:
                return self._client.models.generate_content(
                    model=self.model, contents=prompt, config=self._config()
                )
            except Exception as e:
                delay = _retry_delay(e)
                if getattr(e, "code", None) == 429 and (
                    (delay and delay > MAX_RETRY_WAIT) or "limit: 0" in str(e)
                ):
                    raise QuotaExhaustedError(
                        f"No Gemini quota left for {self.model} ({_short_error(e)}). "
                        "Try a model your key can use (e.g. --model gemini-3.5-flash) or enable billing."
                    ) from e
                if not _is_retryable(e) or attempt == self.max_retries:
                    raise GeminiError(f"Gemini call failed ({_short_error(e)})") from e
                # 2s, 4s, 8s, ... capped at 60s, plus jitter so parallel workers don't retry together.
                time.sleep(max(delay or 0, min(60, 2 ** (attempt + 1))) + random.uniform(0, 1))

    def generate_fix(self, prompt: str) -> GeminiResult:
        """Send a repair prompt (see prompt.build_prompt) and return the fixed file."""
        response = self._call(prompt)

        candidates = getattr(response, "candidates", None) or []
        if not candidates:
            feedback = getattr(response, "prompt_feedback", None)
            raise GeminiError(f"Gemini returned no answer (prompt blocked?): {feedback}")

        finish_reason = str(getattr(candidates[0].finish_reason, "name", candidates[0].finish_reason))
        if finish_reason == "MAX_TOKENS":
            raise GeminiError("Gemini hit max_output_tokens, so the fixed file is cut off.")
        if finish_reason not in {"STOP", "None", "FINISH_REASON_UNSPECIFIED"}:
            raise GeminiError(f"Gemini stopped early: {finish_reason}")

        text = response.text or ""
        if not text.strip():
            raise GeminiError("Gemini returned an empty file.")

        usage = {}
        meta = getattr(response, "usage_metadata", None)
        if meta is not None:
            usage = {
                "prompt_tokens": getattr(meta, "prompt_token_count", None),
                "output_tokens": getattr(meta, "candidates_token_count", None),
                "thinking_tokens": getattr(meta, "thoughts_token_count", None),
            }

        return GeminiResult(text=strip_code_fences(text), model=self.model, finish_reason=finish_reason, usage=usage)
