"""
Airlock: Deterministic sub-10ms ingress security guardrail and token conservation engine.
Zero-LLM overhead regex compilation for prompt injection, jailbreak attempts,
SQL destruction attacks, credential exfiltration, and resource exhaustion DoS.
"""

import enum
import math
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


class ViolationCategory(str, enum.Enum):
    """
    Deterministic violation categories enforced by the Airlock policy engine.
    """

    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    JAILBREAK_ATTEMPT = "JAILBREAK_ATTEMPT"
    SQL_INJECTION = "SQL_INJECTION"
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"
    PAYLOAD_SIZE_EXCEEDED = "PAYLOAD_SIZE_EXCEEDED"
    TOKEN_BUDGET_EXCEEDED = "TOKEN_BUDGET_EXCEEDED"
    MALFORMED_INPUT = "MALFORMED_INPUT"


@dataclass(frozen=True)
class AirlockResult:
    """
    Immutable audit inspection result returned by the Airlock filter.
    """

    passed: bool
    violation_category: Optional[ViolationCategory] = None
    matched_pattern: Optional[str] = None
    reason: Optional[str] = None
    scan_time_ms: float = 0.0
    estimated_tokens: int = 0
    tokens_conserved: int = 0


# ==============================================================================
# Compile-Time Deterministic Regex Rules (Zero Runtime Recompilation Overhead)
# ==============================================================================

# 1. System Prompt Leak & Override Patterns
SYSTEM_PROMPT_LEAK_PATTERNS = [
    re.compile(
        r"\b(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|initial|preceding|above)\s+(instructions|directives|prompts|rules|system\s+prompts?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(show|reveal|display|output|print|repeat|dump|tell)(\s+me)?\s+(all\s+)?(the\s+|your\s+)?(initial|original|core|system|hidden)\s+(instructions?|prompts?|rules?|directives?|guidelines?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(output|print|show)(\s+me)?\s+(your\s+)?(system\s+)?(prompt|instructions?)\s+verbatim\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwhat\s+(are|were|is)\s+(all\s+)?(the\s+|your\s+)?(exact\s+)?(system\s+prompt|initial\s+instructions|system\s+instructions|core\s+directives|system\s+rules)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(print|repeat|output)\s+(the\s+)?(text|content)\s+(above|prior)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\brepeat\s+everything\s+(written\s+)?(before|above)\b",
        re.IGNORECASE,
    ),
]

# 2. Jailbreak, Persona Bypass & Alignment Stripping Patterns
JAILBREAK_PATTERNS = [
    re.compile(
        r"\b(you\s+are\s+now|act\s+as|simulate|pretend\s+to\s+be)\s+(DAN|do\s+anything\s+now|AIM|evil\s+confidant|unfiltered\s+ai|an\s+anarchist|chaos\s+gpt)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(DAN|jailbreak|developer\s+mode|unrestricted\s+mode)\s+(mode\s+)?(enabled|activated|on|engaged|active)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(bypass|disable|ignore|strip|remove|circumvent)\s+(all\s+)?(safety|security|ethical|content|policy|openai|anthropic|guardrails?)\s+(filters|rules|guardrails|policies|guidelines|protocols)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(bypass|circumvent|override|disable)\s+(all\s+)?(security\s+guardrails?|security\s+filters?|safety\s+guardrails?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(base64_decode|b64decode|decode_base64|rot13|hex_decode)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bpretend\s+(you\s+have\s+no\s+rules|there\s+are\s+no\s+(restrictions|rules|boundaries|guidelines))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(you\s+must\s+)?always\s+comply\s+without\s+(refusal|hesitation|restrictions|morals)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bgenerate\s+content\s+without\s+(any\s+)?censorship\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bfor\s+the\s+rest\s+of\s+this\s+conversation,\s+you\s+have\s+been\s+freed\b",
        re.IGNORECASE,
    ),
]

# 3. SQL Injection & Destructive Query Signatures
SQL_INJECTION_PATTERNS = [
    re.compile(
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX|PROCEDURE)\s+[`\"']?[a-zA-Z0-9_\*\.]+[`\"']?",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bTRUNCATE\s+TABLE\s+[`\"']?[a-zA-Z0-9_\.]+[`\"']?",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bALTER\s+TABLE\s+[`\"']?[a-zA-Z0-9_\.]+[`\"']?\s+DROP\s+COLUMN\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bDELETE\s+FROM\s+[`\"']?[a-zA-Z0-9_\.]+[`\"']?\s+WHERE\s+(1\s*=\s*1|'1'\s*=\s*'1'|true)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r";\s*--",
    ),
    re.compile(
        r"\bUNION\s+(ALL\s+)?SELECT\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"'\s*(OR|AND)\s+('?1'?\s*=\s*'?1'|true)\s*(--|#|\/\*)?",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bEXEC(\s+sp_executesql|\s+xp_cmdshell)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r";\s*DROP\s+(TABLE|DATABASE)\b",
        re.IGNORECASE,
    ),
]

# 4. Credential Exfiltration, Private Keys & Secret Scraping Patterns
CREDENTIAL_PATTERNS = [
    # AWS Access Key ID
    re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    # AWS Secret Key assignment syntax
    re.compile(
        r"(?i)\b(aws_secret_access_key|aws_access_key_id|api[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9/+=]{16,}['\"]"
    ),
    # PEM Private Keys (RSA, DSA, EC, OPENSSH)
    re.compile(r"-----BEGIN\s+([A-Z0-9_-]+\s+)?PRIVATE\s+KEY-----"),
    # Standard JSON Web Token (JWT) three-segment base64
    re.compile(r"\beyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b"),
    # Credential scraping reconnaissance prompts
    re.compile(
        r"\b(dump|list|extract|exfiltrate|reveal|leak|print)\s+(all\s+)?(passwords|api[_-]?keys?|secret[_-]?keys?|auth[_-]?tokens?|credentials)\s+(from|in)\b",
        re.IGNORECASE,
    ),
    # Database connection URIs containing embedded passwords
    re.compile(
        r"\b(postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9.-]+",
        re.IGNORECASE,
    ),
]


class Airlock:
    """
    High-speed deterministic ingress guardrail.
    Enforces 'Rules Engine Decides, AI Explains' with sub-10ms latency.
    """

    def __init__(
        self,
        enabled: bool = True,
        max_prompt_length: int = 16384,
        max_total_tokens: int = 8192,
        strict_jailbreak: bool = True,
        strict_sql: bool = True,
        strict_credentials: bool = True,
    ):
        self.enabled = enabled
        self.max_prompt_length = max_prompt_length
        self.max_total_tokens = max_total_tokens
        self.strict_jailbreak = strict_jailbreak
        self.strict_sql = strict_sql
        self.strict_credentials = strict_credentials

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """
        Fast deterministic token estimation without neural tokenizer overhead.
        Empirical ratio: ~4 characters per token + 1 token per whitespace separator.
        """
        if not text:
            return 0
        char_count = len(text)
        word_count = len(text.split())
        # Blended heuristic: average of char-based and word-based estimation
        est = int(math.ceil((char_count / 4.0 + word_count * 1.25) / 2.0))
        return max(1, est)

    def scan_text(self, text: str) -> Tuple[bool, Optional[ViolationCategory], Optional[str], Optional[str]]:
        """
        Scan a single string across all active deterministic regex rules.
        Returns: (passed, category, matched_pattern, reason)
        """
        if not text:
            return True, None, None, None

        # Check raw payload size limit
        if len(text) > self.max_prompt_length:
            return (
                False,
                ViolationCategory.PAYLOAD_SIZE_EXCEEDED,
                f"length > {self.max_prompt_length}",
                f"Message content of {len(text)} characters exceeds maximum allowable limit of {self.max_prompt_length}.",
            )

        # 1. System Prompt Leak Checks
        if self.strict_jailbreak:
            for pattern in SYSTEM_PROMPT_LEAK_PATTERNS:
                match = pattern.search(text)
                if match:
                    return (
                        False,
                        ViolationCategory.SYSTEM_PROMPT_LEAK,
                        pattern.pattern,
                        f"System prompt leak or instruction override detected: '{match.group(0)}'",
                    )

        # 2. Jailbreak / DAN Checks
        if self.strict_jailbreak:
            for pattern in JAILBREAK_PATTERNS:
                match = pattern.search(text)
                if match:
                    return (
                        False,
                        ViolationCategory.JAILBREAK_ATTEMPT,
                        pattern.pattern,
                        f"Adversarial jailbreak signature detected: '{match.group(0)}'",
                    )

        # 3. SQL Injection / Drops Checks
        if self.strict_sql:
            for pattern in SQL_INJECTION_PATTERNS:
                match = pattern.search(text)
                if match:
                    return (
                        False,
                        ViolationCategory.SQL_INJECTION,
                        pattern.pattern,
                        f"Destructive SQL injection pattern detected: '{match.group(0)}'",
                    )

        # 4. Credential / Secret Exfiltration Checks
        if self.strict_credentials:
            for pattern in CREDENTIAL_PATTERNS:
                match = pattern.search(text)
                if match:
                    return (
                        False,
                        ViolationCategory.CREDENTIAL_EXFILTRATION,
                        pattern.pattern,
                        f"Secret key, credential, or unauthorized exfiltration pattern detected: '{match.group(0)}'",
                    )

        return True, None, None, None

    def inspect_messages(self, messages: List[Dict[str, Any]]) -> AirlockResult:
        """
        Execute sub-10ms deterministic guardrail checks on a list of chat completion messages.
        Calculates exact tokens conserved upon violation blocking.
        """
        start_perf = time.perf_counter()

        if not self.enabled:
            duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
            return AirlockResult(passed=True, scan_time_ms=duration_ms)

        if not messages or not isinstance(messages, list):
            duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
            return AirlockResult(
                passed=False,
                violation_category=ViolationCategory.MALFORMED_INPUT,
                reason="Messages array cannot be empty or non-list.",
                scan_time_ms=duration_ms,
            )

        total_tokens = 0
        combined_text = []

        # Scan each message content
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
                return AirlockResult(
                    passed=False,
                    violation_category=ViolationCategory.MALFORMED_INPUT,
                    reason=f"Message index {idx} is not a valid dictionary object.",
                    scan_time_ms=duration_ms,
                )

            content = msg.get("content", "")
            if isinstance(content, list):
                # Handle OpenAI multi-part content (e.g. text + images)
                text_parts = [
                    part.get("text", "")
                    for part in content
                    if isinstance(part, dict) and part.get("type") == "text"
                ]
                content_str = " ".join(text_parts)
            elif isinstance(content, str):
                content_str = content
            else:
                content_str = str(content) if content is not None else ""

            combined_text.append(content_str)
            msg_tokens = self.estimate_tokens(content_str)
            total_tokens += msg_tokens

            passed, category, pattern, reason = self.scan_text(content_str)
            if not passed:
                duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
                # Token conservation calculation: input tokens blocked + default estimated response tokens (250)
                conserved = total_tokens + 250
                return AirlockResult(
                    passed=False,
                    violation_category=category,
                    matched_pattern=pattern,
                    reason=reason,
                    scan_time_ms=duration_ms,
                    estimated_tokens=total_tokens,
                    tokens_conserved=conserved,
                )

        # Check total token budget guardrail
        if total_tokens > self.max_total_tokens:
            duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
            conserved = total_tokens + 250
            return AirlockResult(
                passed=False,
                violation_category=ViolationCategory.TOKEN_BUDGET_EXCEEDED,
                matched_pattern=f"tokens > {self.max_total_tokens}",
                reason=f"Total estimated prompt tokens ({total_tokens}) exceeds maximum allowed budget ({self.max_total_tokens}).",
                scan_time_ms=duration_ms,
                estimated_tokens=total_tokens,
                tokens_conserved=conserved,
            )

        duration_ms = round((time.perf_counter() - start_perf) * 1000.0, 4)
        return AirlockResult(
            passed=True,
            scan_time_ms=duration_ms,
            estimated_tokens=total_tokens,
            tokens_conserved=0,
        )
