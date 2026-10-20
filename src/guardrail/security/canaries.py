"""Synthetic Canary Token Generation, Detection, and Redaction.

Security Design:
1. Purely Synthetic: All canary tokens adhere to the deterministic pattern:
   CANARY{SYNTH_[A-Z0-9_]+}
   No real secrets or development environment tokens are ever used.
2. Output Scrubbing: In Hardened mode, all text produced by the model is scanned
   before delivery to the user or caller. If a canary token pattern is identified,
   it is immediately redacted to '[REDACTED_CANARY_TOKEN]' and flagged with a security alert.
"""

import re
from typing import List, Tuple

CANARY_PATTERN = re.compile(r"CANARY\{[A-Za-z0-9_]+\}")

KNOWN_SYNTHETIC_CANARIES = [
    "CANARY{SYNTH_VPN_GATEWAY_ROOT_KEY_992}",
    "CANARY{SYNTH_EXEC_BOARDROOM_LEAK_441}",
]


class CanaryDetector:
    """Detects and redacts synthetic canary tokens in agent output streams."""

    def __init__(self, pattern: re.Pattern = CANARY_PATTERN):
        self.pattern = pattern

    def find_canaries(self, text: str) -> List[str]:
        """Return all synthetic canary tokens found in the input text."""
        if not text:
            return []
        return list(set(self.pattern.findall(text)))

    def redact_canaries(self, text: str) -> Tuple[str, int, List[str]]:
        """Redact any synthetic canary tokens and return count and list of leaked tokens.

        Returns:
            Tuple of (redacted_text, total_redactions_made, list_of_unique_tokens_found)
        """
        if not text:
            return text, 0, []

        tokens_found = self.find_canaries(text)
        if not tokens_found:
            return text, 0, []

        redacted_text = self.pattern.sub("[REDACTED_CANARY_TOKEN]", text)
        return redacted_text, len(tokens_found), tokens_found
