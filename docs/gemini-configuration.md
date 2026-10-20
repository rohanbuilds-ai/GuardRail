# Optional Google Gemini Configuration & Zero-Cost Policy

## 1. Zero-Cost Policy by Default

GuardRail is designed to be **100% free and runnable offline out of the box**.
- The default provider is `mock` (`MockLLMProvider`).
- All unit, integration, and red-team tests run against the mock provider with **zero network requests, zero latency jitter, and zero API costs**.
- You do **not** need a paid credit card, GCP billing account, or paid API subscription to run, evaluate, or demonstrate this project.

---

## 2. When to Use Google Gemini

Live Gemini integration is strictly **optional**. You may choose to enable it if you wish to observe non-deterministic live model reasoning, live tool calling, and prompt injection dynamics against Google's modern frontier models.

Supported model: `gemini-2.5-flash` (via the official `google-genai` Python SDK).

---

## 3. How to Configure Gemini (Free Tier)

Google AI Studio offers a generous **Free Tier** for developers that requires no paid billing:

1. Visit [Google AI Studio](https://aistudio.google.com/).
2. Sign in with your Google account and create a free API Key.
3. Review current free tier rate limits (e.g. 15 requests per minute, 1,500 requests per day on free tier).
4. In your GuardRail root directory, copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
5. Edit `.env` to configure the provider:
   ```env
   GUARDRAIL_PROVIDER=gemini
   GEMINI_API_KEY=AIzaSy...your_actual_key_here
   ```
6. Start the server:
   ```powershell
   uv run uvicorn guardrail.main:app --reload
   ```

---

## 4. Automatic Safe Fallback

If `GUARDRAIL_PROVIDER=gemini` is selected but `GEMINI_API_KEY` is missing, empty, or fails to initialize:
- GuardRail logs a clear warning:
  `"Gemini provider was requested but GEMINI_API_KEY is not set. Falling back safely to deterministic MockLLMProvider (zero-cost offline mode)."`
- The application automatically continues in mock mode without crashing or hanging.
