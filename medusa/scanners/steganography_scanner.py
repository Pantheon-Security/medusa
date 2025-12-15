#!/usr/bin/env python3
"""
MEDUSA Steganography Injection Scanner
Detects hidden payloads and obfuscated content in multimodal AI inputs

Based on:
- "Generative AI Security: Theories and Practices" Chapter on Adversarial Attacks
- Multimodal AI security research
- Prompt injection obfuscation techniques

Detects:
- Steganographic patterns in image/media processing code
- Hidden Unicode characters (zero-width, homoglyphs)
- Base64/encoded content in prompts
- HTML/XML comment hiding
- Control token injection
- Invisible text patterns
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple

from medusa.scanners.base import BaseScanner, ScannerResult, ScannerIssue, Severity


class SteganographyScanner(BaseScanner):
    """
    Steganography and Hidden Payload Scanner

    Scans for:
    - STG001: Zero-width Unicode characters in user input handling
    - STG002: Homoglyph/lookalike character detection gaps
    - STG003: Base64 content in prompt/input handling
    - STG004: HTML/XML comment processing without sanitization
    - STG005: Image metadata extraction without validation
    - STG006: Audio/video hidden data extraction
    - STG007: Control token patterns in user input
    - STG008: Invisible/hidden text CSS patterns
    - STG009: LSB (Least Significant Bit) steganography patterns
    - STG010: Multimodal input concatenation without sanitization
    """

    # STG001: Zero-width Unicode handling gaps
    ZERO_WIDTH_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Code that processes user input but doesn't filter zero-width chars
        (r'(user_input|prompt|message|text).*(?:strip|trim)\(\)(?!.*[\u200b\u200c\u200d\ufeff])',
         'Input sanitization without zero-width character filtering', Severity.MEDIUM),
        (r'input\s*=\s*request\.',
         'Direct request input (check for zero-width character filtering)', Severity.LOW),

        # Zero-width chars in strings (potential payload)
        (r'[\u200b\u200c\u200d\ufeff\u2060\u180e]',
         'Zero-width Unicode character detected (potential hidden payload)', Severity.HIGH),

        # Regex that doesn't account for zero-width
        (r'\\s\+.*user|user.*\\s\+',
         'Whitespace regex may not catch zero-width characters', Severity.LOW),
    ]

    # STG002: Homoglyph/lookalike character gaps
    HOMOGLYPH_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Cyrillic lookalikes
        (r'[\u0430\u0435\u043e\u0440\u0441\u0445]',
         'Cyrillic homoglyph detected (looks like Latin a/e/o/p/c/x)', Severity.MEDIUM),
        # Greek lookalikes
        (r'[\u03b1\u03b5\u03bf]',
         'Greek homoglyph detected (looks like Latin a/e/o)', Severity.MEDIUM),
        # Mathematical symbols
        (r'[\u2212\u2010\u2011]',
         'Mathematical minus/hyphen (looks like ASCII dash)', Severity.LOW),
        # Full-width characters
        (r'[\uff01-\uff5e]',
         'Full-width ASCII characters detected (obfuscation)', Severity.MEDIUM),
    ]

    # STG003: Base64 in prompts/inputs
    BASE64_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'base64\.b64decode\s*\(\s*(?:user|input|prompt|request)',
         'Base64 decoding user input (hidden payload risk)', Severity.HIGH),
        (r'atob\s*\(\s*(?:user|input|prompt|request)',
         'JavaScript atob() on user input (hidden payload)', Severity.HIGH),
        (r'(?:prompt|input|message).*base64',
         'Base64 content in prompt/input handling', Severity.MEDIUM),
        (r'data:.*base64',
         'Data URI with base64 (check for payload)', Severity.MEDIUM),
        # Detect inline base64 patterns
        (r'["\'][A-Za-z0-9+/]{50,}={0,2}["\']',
         'Long base64 string literal (potential hidden content)', Severity.LOW),
    ]

    # STG004: HTML/XML comment processing
    HTML_COMMENT_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'<!--.*(?:ignore|forget|disregard|system|admin|root).*-->',
         'HTML comment with suspicious keywords (injection attempt)', Severity.CRITICAL),
        (r'BeautifulSoup\(.*\)(?!.*comments\s*=\s*False)',
         'BeautifulSoup without comment stripping', Severity.MEDIUM),
        (r'lxml\.etree.*(?:user|input|prompt)',
         'XML parsing user input (check for comment/PI injection)', Severity.MEDIUM),
        (r'\.innerHTML\s*=.*(?:user|input|prompt)',
         'innerHTML with user input (hidden content risk)', Severity.HIGH),
    ]

    # STG005: Image metadata extraction
    IMAGE_METADATA_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:exif|EXIF).*(?:user|upload|input)',
         'EXIF extraction from user upload (hidden data risk)', Severity.MEDIUM),
        (r'PIL\.Image\.open\(.*(?:user|upload)',
         'PIL image open on user upload (check metadata)', Severity.LOW),
        (r'(?:getexif|get_exif|read_exif)\s*\(',
         'EXIF reading function (validate before LLM processing)', Severity.LOW),
        (r'image\.info|img\.info',
         'Image info/metadata access (may contain hidden data)', Severity.LOW),
        (r'piexif\.load|exifread\.process_file',
         'EXIF library usage (sanitize before LLM input)', Severity.MEDIUM),
    ]

    # STG006: Audio/video hidden data
    AUDIO_VIDEO_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:ffmpeg|FFmpeg).*-metadata',
         'FFmpeg metadata handling (hidden data vector)', Severity.LOW),
        (r'(?:audio|video).*(?:transcript|transcribe).*(?:user|upload)',
         'Transcription of user media (steganographic audio risk)', Severity.MEDIUM),
        (r'whisper.*(?:user|upload|input)',
         'Whisper transcription on user input (hidden audio patterns)', Severity.MEDIUM),
        (r'ID3|id3.*(?:user|upload)',
         'ID3 tag reading from user audio (hidden data)', Severity.MEDIUM),
    ]

    # STG007: Control token patterns
    CONTROL_TOKEN_PATTERNS: List[Tuple[str, str, Severity]] = [
        # Llama/Mistral tokens
        (r'\[INST\]|\[/INST\]',
         'Llama instruction tokens in content (control token injection)', Severity.CRITICAL),
        (r'\[SYS\]|\[/SYS\]',
         'System tokens in content (control token injection)', Severity.CRITICAL),
        # ChatML tokens
        (r'<\|im_start\|>|<\|im_end\|>',
         'ChatML control tokens (delimiter injection)', Severity.CRITICAL),
        (r'<\|system\|>|<\|user\|>|<\|assistant\|>',
         'Role delimiter tokens in content', Severity.CRITICAL),
        # OpenAI/Claude markers
        (r'<\|endoftext\|>',
         'End-of-text token in content (sequence break attack)', Severity.HIGH),
        (r'Human:|Assistant:|System:',
         'Role markers in user content (role confusion attack)', Severity.HIGH),
        # Generic delimiters
        (r'###\s*(?:System|User|Assistant|Instruction)',
         'Markdown role delimiter in content', Severity.MEDIUM),
    ]

    # STG008: Invisible text patterns
    INVISIBLE_TEXT_PATTERNS: List[Tuple[str, str, Severity]] = [
        # CSS hiding
        (r'display:\s*none.*(?:prompt|instruction|command)',
         'CSS hidden text with prompt keywords', Severity.HIGH),
        (r'visibility:\s*hidden.*(?:prompt|instruction)',
         'CSS invisible text with prompt keywords', Severity.HIGH),
        (r'font-size:\s*0',
         'Zero font-size (invisible text technique)', Severity.MEDIUM),
        (r'color:\s*(?:white|#fff|#ffffff|transparent).*background.*(?:white|#fff)',
         'White text on white background (invisible)', Severity.MEDIUM),
        # Hidden HTML tags
        (r'<span[^>]*style=["\'][^"\']*(?:display:\s*none|visibility:\s*hidden)',
         'Hidden span element', Severity.MEDIUM),
        (r'<div[^>]*hidden[^>]*>',
         'Hidden div element', Severity.MEDIUM),
    ]

    # STG009: LSB Steganography patterns
    LSB_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'&\s*0x01|&\s*1(?!\d)',
         'LSB extraction pattern (steganography decoding)', Severity.MEDIUM),
        (r'(?:pixel|byte)\s*&\s*(?:0x01|1)',
         'Pixel LSB access (steganography)', Severity.MEDIUM),
        (r'stegano|Stegano|LSBSteg',
         'Steganography library usage', Severity.HIGH),
        (r'(?:encode|decode).*(?:image|pixel).*(?:message|text|data)',
         'Image encoding/decoding with text (steganography)', Severity.MEDIUM),
    ]

    # STG010: Multimodal concatenation
    MULTIMODAL_PATTERNS: List[Tuple[str, str, Severity]] = [
        (r'(?:image|audio|video).*\+.*(?:text|prompt)',
         'Multimodal concatenation (sanitize each modality)', Severity.MEDIUM),
        (r'(?:vision|multimodal).*(?:user|input).*(?:text|message)',
         'Multimodal user input processing', Severity.LOW),
        (r'(?:ocr|OCR).*(?:prompt|llm|generate)',
         'OCR text to LLM (hidden text in images risk)', Severity.HIGH),
        (r'(?:extract_text|read_text).*(?:image|screenshot)',
         'Text extraction from image (hidden payload vector)', Severity.MEDIUM),
    ]

    # Good patterns (sanitization)
    SANITIZATION_PATTERNS = [
        r'sanitize|normalize|clean|filter|escape|validate',
        r'remove_zero_width|strip_invisible',
        r'unicode\.normalize|unicodedata\.normalize',
        r'html\.escape|markupsafe\.escape',
        r'bleach\.clean',
    ]

    def __init__(self):
        super().__init__()

    def get_tool_name(self) -> str:
        return "python"  # Built-in scanner

    def get_file_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php"]

    def is_available(self) -> bool:
        """Built-in scanner, always available"""
        return True

    def scan_file(self, file_path: Path) -> ScannerResult:
        """Wrapper for scan() to match abstract method signature"""
        return self.scan(file_path)

    def scan(self, file_path: Path, content: Optional[str] = None) -> ScannerResult:
        """Scan for steganography and hidden payload vulnerabilities"""
        start_time = time.time()
        issues: List[ScannerIssue] = []

        try:
            if content is None:
                content = file_path.read_text(encoding="utf-8", errors="replace")

            # Check if file handles user input or multimodal content
            relevant_indicators = [
                'input', 'user', 'prompt', 'message', 'upload', 'image',
                'audio', 'video', 'text', 'ocr', 'vision', 'multimodal',
                'llm', 'gpt', 'claude', 'anthropic', 'openai',
            ]
            content_lower = content.lower()

            if not any(ind in content_lower for ind in relevant_indicators):
                return ScannerResult(
                    scanner_name=self.name,
                    file_path=str(file_path),
                    issues=[],
                    scan_time=time.time() - start_time,
                    success=True,
                )

            # Check for sanitization patterns
            has_sanitization = any(
                re.search(p, content, re.IGNORECASE)
                for p in self.SANITIZATION_PATTERNS
            )

            lines = content.split('\n')

            # STG001: Zero-width Unicode
            issues.extend(self._check_patterns(
                content, lines, self.ZERO_WIDTH_PATTERNS, "STG001"
            ))

            # STG002: Homoglyphs
            issues.extend(self._check_patterns(
                content, lines, self.HOMOGLYPH_PATTERNS, "STG002"
            ))

            # STG003: Base64 in inputs
            issues.extend(self._check_patterns(
                content, lines, self.BASE64_PATTERNS, "STG003"
            ))

            # STG004: HTML/XML comments
            issues.extend(self._check_patterns(
                content, lines, self.HTML_COMMENT_PATTERNS, "STG004"
            ))

            # STG005: Image metadata
            issues.extend(self._check_patterns(
                content, lines, self.IMAGE_METADATA_PATTERNS, "STG005"
            ))

            # STG006: Audio/video hidden data
            issues.extend(self._check_patterns(
                content, lines, self.AUDIO_VIDEO_PATTERNS, "STG006"
            ))

            # STG007: Control tokens
            issues.extend(self._check_patterns(
                content, lines, self.CONTROL_TOKEN_PATTERNS, "STG007"
            ))

            # STG008: Invisible text
            issues.extend(self._check_patterns(
                content, lines, self.INVISIBLE_TEXT_PATTERNS, "STG008"
            ))

            # STG009: LSB steganography
            issues.extend(self._check_patterns(
                content, lines, self.LSB_PATTERNS, "STG009"
            ))

            # STG010: Multimodal concatenation
            issues.extend(self._check_patterns(
                content, lines, self.MULTIMODAL_PATTERNS, "STG010"
            ))

            # Reduce severity if sanitization is present
            if has_sanitization:
                for issue in issues:
                    if issue.severity == Severity.HIGH:
                        issue.severity = Severity.MEDIUM
                    elif issue.severity == Severity.MEDIUM:
                        issue.severity = Severity.LOW

            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=issues,
                scan_time=time.time() - start_time,
                success=True,
            )

        except Exception as e:
            return ScannerResult(
                scanner_name=self.name,
                file_path=str(file_path),
                issues=[],
                scan_time=time.time() - start_time,
                success=False,
                error_message=str(e),
            )

    def _check_patterns(
        self,
        content: str,
        lines: List[str],
        patterns: List[Tuple[str, str, Severity]],
        rule_id: str
    ) -> List[ScannerIssue]:
        """Check content against a list of patterns"""
        issues = []
        seen_messages = set()

        for pattern, message, severity in patterns:
            for i, line in enumerate(lines, 1):
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        if message not in seen_messages:
                            issues.append(ScannerIssue(
                                rule_id=rule_id,
                                severity=severity,
                                message=f"{message} - sanitize/validate before LLM processing",
                                line=i,
                                column=1,
                            ))
                            seen_messages.add(message)
                            break
                except re.error:
                    # Skip invalid regex patterns
                    continue

        return issues
