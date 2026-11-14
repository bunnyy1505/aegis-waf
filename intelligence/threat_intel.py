"""
Threat Intelligence and Payload Scoring Engine for Agentic AI Firewall.

This module provides a local threat intelligence database, pattern matching
engines for detecting web application and injection attacks (SQLi, XSS, Path
Traversal, Command Injection, Prompt Injection), user agent / bot fingerprinting,
IP reputation scoring, and an asynchronous payload scanner.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import html
import ipaddress
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("firewall.threat_intel")

# ============================================================================
# Attack Pattern Definitions (Compiled Regular Expressions)
# ============================================================================

SQLI_PATTERNS: List[re.Pattern] = [
    # UNION SELECT queries
    re.compile(r"(?i)\bunion(\s+all)?\s+select\b"),
    # Common DDL/DML clauses with standard targets
    re.compile(
        r"(?i)\b(select|insert\s+into|update|delete\s+from|drop\s+table|drop\s+database|"
        r"alter\s+table|truncate\s+table|create\s+table|exec(\s+xp_cmdshell)?|execute)\b"
    ),
    # Boolean-based tautology patterns (e.g., ' OR '1'='1', " AND 1=1)
    re.compile(r"(?i)\b(or|and)\b\s+['\"]?(\d+|[a-z]+)['\"]?\s*=\s*['\"]?\2['\"]?"),
    re.compile(r"(?i)\b(or|and)\b\s+['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*['\"]"),
    re.compile(r"(?i)\b(or|and)\b\s+\d+\s*=\s*\d+"),
    # SQL comment terminations and stacked queries
    re.compile(r"(?i)(--|#|/\*.*?\*/|;\s*$)"),
    re.compile(r"(?i)admin'(\s*(--|#|/\*))"),
    # Time-based blind injection primitives
    re.compile(
        r"(?i)\b(waitfor\s+delay\s+['\"]\d+:\d+:\d+['\"]|sleep\s*\(\s*\d+\s*\)|"
        r"benchmark\s*\(\s*\d+,\s*.*?\)|pg_sleep\s*\(\s*\d+\s*\))"
    ),
    # Database fingerprinting and metadata extraction functions
    re.compile(
        r"(?i)\b(information_schema\.(tables|columns|schemata)|schema\(\)|database\(\)|"
        r"version\(\)|current_user|user\(\)|session_user|system_user)\b"
    ),
    # Error-based payload functions
    re.compile(
        r"(?i)\b(extractvalue|updatexml|floor\s*\(\s*rand\s*\(|geometrycollection|"
        r"multipointrange|linestring)\s*\("
    ),
    # File manipulation and bulk data exfiltration
    re.compile(r"(?i)\b(load_file\s*\(|into\s+(outfile|dumpfile)\b)"),
    # Group concatenation / string aggregation
    re.compile(r"(?i)\b(group_concat|char\s*\(|concat\s*\(|concat_ws)\b"),
    # Stacked execution separators
    re.compile(r"(?i);\s*(select|insert|update|delete|drop|alter|exec)\b"),
]

XSS_PATTERNS: List[re.Pattern] = [
    # Explicit script tags and contents
    re.compile(r"(?i)<\s*script\b[^>]*>.*?(<\s*/\s*script\s*>)?", re.DOTALL),
    # Dangerous URI schemes in hyperlinks or source attributes
    re.compile(r"(?i)(javascript|vbscript|livescript)\s*:\s*[^\s\"'>]+"),
    # Data URI schemes delivering HTML, JavaScript, or executable SVG
    re.compile(
        r"(?i)data\s*:\s*(text\/html|application\/x-javascript|text\/javascript|"
        r"image\/svg\+xml)[^\"'>]*"
    ),
    # Inline DOM event handlers (e.g., onload=, onerror=, onclick=)
    re.compile(
        r"(?i)\bon(load|unload|click|dblclick|mousedown|mouseup|mouseover|mousemove|"
        r"mouseout|mouseenter|mouseleave|keydown|keypress|keyup|focus|blur|change|"
        r"submit|reset|select|input|error|animationend|transitionend|toggle)\s*="
    ),
    # Risky HTML container and embedding elements
    re.compile(
        r"(?i)<\s*(iframe|object|embed|applet|meta|base|link|svg|video|audio|"
        r"body|style|form)\b[^>]*\b(src|href|data|action|formaction|poster|style)\s*=[^>]*>"
    ),
    # DOM sink manipulation and cookie theft
    re.compile(
        r"(?i)\bdocument\.(cookie|location|write|writeln|domain|referrer)\b"
    ),
    re.compile(r"(?i)\bwindow\.(location|open|navigate)\b"),
    # JavaScript execution sinks and dialog popups
    re.compile(r"(?i)\b(eval|alert|prompt|confirm)\s*\([^)]*\)"),
    re.compile(r"(?i)\b(settimeout|setinterval)\s*\(\s*['\"][^'\"]*['\"]"),
    # SVG-based vector execution
    re.compile(r"(?i)<\s*svg\b[^>]*\bonload\s*="),
    # Expression / behavior in styles (legacy IE and modern CSS escapes)
    re.compile(r"(?i)expression\s*\([^)]*\)"),
]

PATH_TRAVERSAL_PATTERNS: List[re.Pattern] = [
    # Standard dot-dot-slash patterns for UNIX and Windows
    re.compile(r"(\.\./|\.\.\\)"),
    # URL encoded dot-dot representations
    re.compile(
        r"(?i)(%2e%2e[\/\\]|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c|%2e\.\/|\.%2e\/)"
    ),
    # Double URL-encoded, overlong UTF-8, and Unicode escape sequences
    re.compile(
        r"(?i)(%252e%252e|%c0%ae%c0%ae|%uff0e%uff0e|\xc0\xae\xc0\xae)"
    ),
    # Critical UNIX / Linux system configuration and credentials
    re.compile(
        r"(?i)(\/etc\/(passwd|shadow|group|hosts|issue|sudoers|crontab|"
        r"network\/interfaces|ssh\/sshd_config))"
    ),
    # Linux kernel process and environment runtime files
    re.compile(
        r"(?i)(\/proc\/(self|[0-9]+)\/(environ|cmdline|cwd|fd|maps|status))"
    ),
    # System logs often targeted for log poisoning / traversal
    re.compile(
        r"(?i)(\/var\/log\/(auth\.log|syslog|messages|apache2\/access\.log|nginx\/access\.log))"
    ),
    # Critical Windows configuration and drivers
    re.compile(
        r"(?i)([a-z]:[\/\\]windows[\/\\](system32[\/\\]drivers[\/\\]etc[\/\\]hosts|"
        r"win\.ini|system\.ini|boot\.ini))"
    ),
    # Null-byte injection for file extension bypass
    re.compile(r"(%00|\x00)[\w\.]*"),
    # Recursive multiple path traversal sequences
    re.compile(r"(?i)(\.\.[\/\\]){2,}"),
]

CMD_INJECTION_PATTERNS: List[re.Pattern] = [
    # Shell chaining operators followed by interactive shells
    re.compile(
        r"(?i)(;|\||\|\||&&|\`|\$\()\s*(\/bin\/|\/usr\/bin\/)?(bash|sh|zsh|dash|"
        r"ksh|csh|tcsh|powershell|cmd|cmd\.exe)\b"
    ),
    # Reconnaissance and discovery binary execution
    re.compile(
        r"(?i)(;|\||\|\||&&|\`|\$\()\s*(whoami|id|uname|hostname|ifconfig|"
        r"ipconfig|netstat|route|arp|w|last)\b"
    ),
    # Network retrieval, probing, and reverse shell utilities
    re.compile(
        r"(?i)(;|\||\|\||&&|\`|\$\()\s*(curl|wget|nc|netcat|ncat|socat|fetch|"
        r"ftp|tftp|scp|sftp|ssh)\b"
    ),
    # Linux pseudo-device reverse socket redirection
    re.compile(r"(?i)(\/dev\/(tcp|udp)\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)"),
    # FIFO pipe creation for shell redirection
    re.compile(r"(?i)\b(mkfifo|mknod)\b.*(\/tmp\/[a-z0-9_-]+)"),
    # Interactive / TTY shell spawning commands
    re.compile(r"(?i)\b(bash|sh|zsh)\s+-i\s+>&?\s*\/dev\/"),
    # Destructive filesystem operations
    re.compile(
        r"(?i)(;|\||\|\||&&|\`|\$\()\s*(rm\s+-rf|rmdir\s+\/s|del\s+\/[fqs]|"
        r"format\s+[a-z]:|mkfs)\b"
    ),
    # Inline scripting interpreter invocations
    re.compile(
        r"(?i)(;|\||\|\||&&|\`|\$\()\s*(python|python3|perl|ruby|php|node|lua)\s+-[ec]\b"
    ),
    # Shell variable obfuscation techniques (e.g. ${IFS})
    re.compile(r"\$\{[^}]*(\bIFS\b|PATH|SHELL)[^}]*\}"),
]

# Additional pattern set tailored for Agentic AI Firewalls (LLM prompt injection)
PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(
        r"(?i)\b(ignore\s+(all\s+)?(previous|prior|above)\s+instructions|"
        r"disregard\s+(all\s+)?(previous|prior|system)\s+(instructions|prompts|rules))\b"
    ),
    re.compile(
        r"(?i)\b(you\s+are\s+now\s+(an?\s+unrestricted|DAN|jailbroken|free\s+of\s+rules))\b"
    ),
    re.compile(
        r"(?i)\b(system\s+prompt\s+override|developer\s+mode\s+enabled|"
        r"switch\s+to\s+god\s+mode)\b"
    ),
    re.compile(
        r"(?i)\b(reveal\s+(your\s+)?(initial|internal|system)\s+prompt|"
        r"output\s+initial\s+instructions)\b"
    ),
]


# ============================================================================
# Threat Intelligence Database
# ============================================================================

class ThreatIntelDB:
    """
    Local Threat Intelligence Database and Scoring Engine.

    Maintains known malicious indicators including malicious IP addresses,
    CIDR subnets, bad User-Agent strings, automated bot fingerprints,
    and regular expression rules for cyber attacks and injection attempts.
    """

    DEFAULT_MALICIOUS_IPS: Dict[str, Dict[str, Any]] = {
        "198.51.100.14": {
            "reputation": "malicious",
            "category": "tor_exit_node",
            "threat_level": "high",
            "score": 0.85,
            "description": "Malicious Tor exit node observed in credential stuffing",
        },
        "203.0.113.88": {
            "reputation": "malicious",
            "category": "c2_server",
            "threat_level": "critical",
            "score": 0.98,
            "description": "Cobalt Strike Command & Control active beacon node",
        },
        "198.51.100.201": {
            "reputation": "malicious",
            "category": "brute_force_bot",
            "threat_level": "high",
            "score": 0.88,
            "description": "Distributed API authentication brute-force botnet origin",
        },
        "203.0.113.45": {
            "reputation": "suspicious",
            "category": "vulnerability_scanner",
            "threat_level": "medium",
            "score": 0.70,
            "description": "Automated path traversal and vulnerability scanner host",
        },
        "192.0.2.66": {
            "reputation": "malicious",
            "category": "sqli_probe",
            "threat_level": "critical",
            "score": 0.95,
            "description": "Automated SQL injection probe source affiliated with botnet",
        },
        "198.51.100.73": {
            "reputation": "malicious",
            "category": "ddos_botnet",
            "threat_level": "high",
            "score": 0.92,
            "description": "Mirai botnet variant amplification participant",
        },
        "203.0.113.150": {
            "reputation": "malicious",
            "category": "data_exfiltration",
            "threat_level": "critical",
            "score": 0.99,
            "description": "Staged exfiltration receiver for unauthorized API dumps",
        },
        "192.0.2.119": {
            "reputation": "suspicious",
            "category": "compromised_proxy",
            "threat_level": "medium",
            "score": 0.65,
            "description": "Compromised SOCKS proxy utilized for origin masking",
        },
    }

    DEFAULT_MALICIOUS_SUBNETS: List[str] = [
        "198.51.100.0/28",
        "203.0.113.128/28",
    ]

    DEFAULT_BAD_USER_AGENTS: List[str] = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "gobuster",
        "dirbuster",
        "dirb",
        "wpscan",
        "acunetix",
        "havij",
        "nessus",
        "openvas",
        "arachni",
        "burpsuite",
        "burpcollaborator",
        "zaproxy",
        "hydra",
        "medusa",
        "commix",
        "shodan",
        "censys",
        "zgrab",
        "morfeus",
        "wfuzz",
        "ffuf",
    ]

    DEFAULT_BOT_FINGERPRINTS: List[Dict[str, Any]] = [
        {
            "pattern": r"(?i)headlesschrome",
            "name": "Headless Chrome",
            "category": "headless_browser",
            "threat_level": "medium",
            "score": 0.65,
        },
        {
            "pattern": r"(?i)phantomjs",
            "name": "PhantomJS",
            "category": "headless_browser",
            "threat_level": "high",
            "score": 0.75,
        },
        {
            "pattern": r"(?i)selenium",
            "name": "Selenium Automation",
            "category": "webdriver",
            "threat_level": "medium",
            "score": 0.65,
        },
        {
            "pattern": r"(?i)puppeteer",
            "name": "Puppeteer Webdriver",
            "category": "headless_browser",
            "threat_level": "medium",
            "score": 0.60,
        },
        {
            "pattern": r"(?i)playwright",
            "name": "Playwright Automation",
            "category": "automation_framework",
            "threat_level": "medium",
            "score": 0.60,
        },
        {
            "pattern": r"(?i)webdriver",
            "name": "Generic WebDriver",
            "category": "automation_framework",
            "threat_level": "medium",
            "score": 0.65,
        },
        {
            "pattern": r"(?i)python-requests",
            "name": "Python Requests Library",
            "category": "scripted_client",
            "threat_level": "low",
            "score": 0.40,
        },
        {
            "pattern": r"(?i)aiohttp",
            "name": "Async Python HTTP Client",
            "category": "scripted_client",
            "threat_level": "low",
            "score": 0.40,
        },
        {
            "pattern": r"(?i)go-http-client",
            "name": "Go HTTP Client",
            "category": "scripted_client",
            "threat_level": "low",
            "score": 0.40,
        },
        {
            "pattern": r"(?i)libwww-perl",
            "name": "Perl LWP Client",
            "category": "scripted_client",
            "threat_level": "medium",
            "score": 0.55,
        },
        {
            "pattern": r"(?i)scrapy",
            "name": "Scrapy Web Spider",
            "category": "crawler",
            "threat_level": "medium",
            "score": 0.50,
        },
        {
            "pattern": r"(?i)curl\/\d",
            "name": "cURL CLI Tool",
            "category": "cli_client",
            "threat_level": "low",
            "score": 0.35,
        },
        {
            "pattern": r"(?i)wget\/\d",
            "name": "Wget CLI Tool",
            "category": "cli_client",
            "threat_level": "low",
            "score": 0.35,
        },
    ]

    def __init__(
        self,
        custom_ips: Optional[Dict[str, Dict[str, Any]]] = None,
        custom_subnets: Optional[List[str]] = None,
        custom_bad_user_agents: Optional[List[str]] = None,
        custom_bot_fingerprints: Optional[List[Dict[str, Any]]] = None,
    ):
        self.malicious_ips: Dict[str, Dict[str, Any]] = (
            dict(self.DEFAULT_MALICIOUS_IPS) if custom_ips is None else dict(custom_ips)
        )

        subnets_raw = (
            self.DEFAULT_MALICIOUS_SUBNETS
            if custom_subnets is None
            else custom_subnets
        )
        self.malicious_subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        for s in subnets_raw:
            try:
                self.malicious_subnets.append(ipaddress.ip_network(s, strict=False))
            except ValueError as err:
                logger.warning("Invalid malicious subnet format %s: %s", s, err)

        self.bad_user_agents: List[str] = (
            list(self.DEFAULT_BAD_USER_AGENTS)
            if custom_bad_user_agents is None
            else list(custom_bad_user_agents)
        )

        self.bot_fingerprints: List[Dict[str, Any]] = (
            list(self.DEFAULT_BOT_FINGERPRINTS)
            if custom_bot_fingerprints is None
            else list(custom_bot_fingerprints)
        )

        # Attack pattern references
        self.sqli_patterns: List[re.Pattern] = SQLI_PATTERNS
        self.xss_patterns: List[re.Pattern] = XSS_PATTERNS
        self.path_traversal_patterns: List[re.Pattern] = PATH_TRAVERSAL_PATTERNS
        self.cmd_injection_patterns: List[re.Pattern] = CMD_INJECTION_PATTERNS
        self.prompt_injection_patterns: List[re.Pattern] = PROMPT_INJECTION_PATTERNS

    def check_ip(self, ip: str) -> dict:
        """
        Validates an IP address and queries the local threat intelligence database.

        Checks exact IP records and CIDR subnet memberships. Returns threat details
        including reputation, score (0.0 to 1.0), and classification category.
        """
        if not ip or not isinstance(ip, str):
            return {
                "ip": ip,
                "is_malicious": False,
                "threat_level": "unknown",
                "score": 0.0,
                "error": "IP address must be a non-empty string",
                "details": {},
            }

        cleaned_ip = ip.strip()

        try:
            ip_obj = ipaddress.ip_address(cleaned_ip)
        except ValueError as err:
            return {
                "ip": cleaned_ip,
                "is_malicious": False,
                "threat_level": "unknown",
                "score": 0.0,
                "error": f"Invalid IP address format: {err}",
                "details": {},
            }

        # 1. Direct IP Lookup
        if cleaned_ip in self.malicious_ips:
            info = self.malicious_ips[cleaned_ip]
            return {
                "ip": cleaned_ip,
                "is_malicious": True,
                "threat_level": info.get("threat_level", "high"),
                "score": float(info.get("score", 0.85)),
                "category": info.get("category", "malicious_ip"),
                "details": info,
            }

        # 2. Subnet Membership Lookup
        for subnet in self.malicious_subnets:
            if ip_obj in subnet:
                return {
                    "ip": cleaned_ip,
                    "is_malicious": True,
                    "threat_level": "high",
                    "score": 0.80,
                    "category": "malicious_subnet",
                    "details": {
                        "reputation": "malicious",
                        "matched_subnet": str(subnet),
                        "description": f"IP resides within blacklisted threat subnet {subnet}",
                    },
                }

        # 3. Clean / Benign IP
        return {
            "ip": cleaned_ip,
            "is_malicious": False,
            "threat_level": "clean",
            "score": 0.0,
            "category": "benign",
            "details": {
                "is_private": ip_obj.is_private,
                "is_loopback": ip_obj.is_loopback,
                "is_multicast": ip_obj.is_multicast,
                "reputation": "clean",
            },
        }

    def scan_payload(self, payload: str) -> dict:
        """
        Performs in-depth pattern matching against the payload string.

        Evaluates raw, URL-decoded, and HTML-unescaped variations to defeat
        obfuscation across SQLi, XSS, Path Traversal, and Command Injection categories.
        """
        if payload is None:
            payload = ""
        elif not isinstance(payload, str):
            payload = str(payload)

        if not payload:
            return {
                "is_threat": False,
                "threat_score": 0.0,
                "categories_detected": [],
                "matches": [],
                "total_matches": 0,
                "highest_severity": "none",
                "analyzed_length": 0,
            }

        # Generate canonical decoding variations
        variants: List[Tuple[str, str]] = [("raw", payload)]

        try:
            url_decoded = urllib.parse.unquote(payload)
            if url_decoded != payload:
                variants.append(("url_decoded", url_decoded))
                double_decoded = urllib.parse.unquote(url_decoded)
                if double_decoded != url_decoded:
                    variants.append(("double_url_decoded", double_decoded))
        except Exception:
            pass

        try:
            html_decoded = html.unescape(payload)
            if html_decoded != payload and all(html_decoded != v[1] for v in variants):
                variants.append(("html_decoded", html_decoded))
        except Exception:
            pass

        attack_categories = [
            ("sqli", self.sqli_patterns, "high"),
            ("xss", self.xss_patterns, "high"),
            ("path_traversal", self.path_traversal_patterns, "high"),
            ("cmd_injection", self.cmd_injection_patterns, "critical"),
            ("prompt_injection", self.prompt_injection_patterns, "high"),
        ]

        raw_matches: List[Dict[str, Any]] = []
        categories_detected: Set[str] = set()
        seen_signatures: Set[Tuple[str, str]] = set()

        for variant_name, text in variants:
            for cat_name, pattern_list, default_severity in attack_categories:
                for pattern in pattern_list:
                    for match in pattern.finditer(text):
                        matched_str = match.group(0)
                        sig = (cat_name, matched_str.strip().lower())
                        if sig in seen_signatures:
                            continue
                        seen_signatures.add(sig)

                        severity = default_severity
                        # Elevation logic for especially critical signatures
                        if cat_name == "sqli" and any(
                            crit in matched_str.lower()
                            for crit in ["union", "drop", "xp_cmdshell", "waitfor", "pg_sleep"]
                        ):
                            severity = "critical"
                        elif cat_name == "xss" and any(
                            crit in matched_str.lower()
                            for crit in ["<script", "document.cookie", "javascript:"]
                        ):
                            severity = "critical"
                        elif cat_name == "path_traversal" and any(
                            crit in matched_str.lower()
                            for crit in ["/etc/passwd", "system32", "%00"]
                        ):
                            severity = "critical"

                        categories_detected.add(cat_name)
                        raw_matches.append({
                            "category": cat_name,
                            "pattern": pattern.pattern,
                            "matched_text": matched_str,
                            "position": (match.start(), match.end()),
                            "severity": severity,
                            "source_variant": variant_name,
                        })

        # Calculate Threat Score
        threat_score = 0.0
        highest_severity = "none"

        if raw_matches:
            severity_weights = {
                "critical": 0.95,
                "high": 0.75,
                "medium": 0.50,
                "low": 0.30,
            }

            max_base = max(severity_weights.get(m["severity"], 0.5) for m in raw_matches)
            highest_severity = "critical" if any(m["severity"] == "critical" for m in raw_matches) else "high"

            # Multi-category bonus reflects targeted complex attack attempts
            category_multiplier = 1.0 + (0.08 * (len(categories_detected) - 1))
            threat_score = min(1.0, max_base * category_multiplier)

        return {
            "is_threat": len(raw_matches) > 0,
            "threat_score": round(threat_score, 4),
            "categories_detected": sorted(list(categories_detected)),
            "matches": raw_matches,
            "total_matches": len(raw_matches),
            "highest_severity": highest_severity,
            "analyzed_length": len(payload),
        }

    def check_user_agent(self, ua: str) -> dict:
        """
        Analyzes a User-Agent string against known attack utilities, scanners,
        and automated bot fingerprints.
        """
        if not ua or not isinstance(ua, str) or not ua.strip():
            return {
                "user_agent": ua or "",
                "is_bad": False,
                "is_bot": True,
                "threat_level": "medium",
                "score": 0.45,
                "category": "anomaly",
                "matched_fingerprint": None,
                "details": "Missing or blank User-Agent header",
            }

        cleaned_ua = ua.strip()
        lower_ua = cleaned_ua.lower()

        # 1. Match against known penetration testing / exploitation tools
        for bad_tool in self.bad_user_agents:
            if bad_tool.lower() in lower_ua:
                return {
                    "user_agent": cleaned_ua,
                    "is_bad": True,
                    "is_bot": True,
                    "threat_level": "critical",
                    "score": 1.0,
                    "category": "attack_tool",
                    "matched_fingerprint": bad_tool,
                    "details": f"User-Agent matches known offensive security scanner: {bad_tool}",
                }

        # 2. Match against automated bot and headless browser fingerprints
        for fp in self.bot_fingerprints:
            pattern = fp["pattern"]
            if re.search(pattern, cleaned_ua):
                return {
                    "user_agent": cleaned_ua,
                    "is_bad": fp["threat_level"] in ("high", "critical"),
                    "is_bot": True,
                    "threat_level": fp.get("threat_level", "medium"),
                    "score": float(fp.get("score", 0.60)),
                    "category": fp.get("category", "automated_agent"),
                    "matched_fingerprint": fp.get("name"),
                    "details": f"User-Agent matched fingerprint: {fp.get('name')}",
                }

        # 3. Legitimate / standard client user agent
        return {
            "user_agent": cleaned_ua,
            "is_bad": False,
            "is_bot": False,
            "threat_level": "clean",
            "score": 0.05,
            "category": "standard_browser",
            "matched_fingerprint": None,
            "details": "Standard client User-Agent",
        }

    def get_threat_score(self, context: dict) -> float:
        """
        Computes a unified, context-aware threat score between 0.0 and 1.0.

        The context dictionary accepts:
          - 'ip': client IP address string
          - 'payload': single payload string, or 'payloads': list of payload strings
          - 'user_agent': client user agent string
          - 'path': requested endpoint path (scanned as an additional payload)
          - 'headers': optional HTTP headers dictionary
        """
        if not context or not isinstance(context, dict):
            return 0.0

        scores: List[float] = []
        weights: List[float] = []

        # 1. Evaluate Payload(s)
        payloads_to_scan: List[str] = []
        if "payload" in context and context["payload"]:
            if isinstance(context["payload"], str):
                payloads_to_scan.append(context["payload"])
            elif isinstance(context["payload"], (list, tuple, set)):
                payloads_to_scan.extend(str(p) for p in context["payload"])

        if "payloads" in context and isinstance(context["payloads"], (list, tuple, set)):
            payloads_to_scan.extend(str(p) for p in context["payloads"])

        # Also inspect request path if present
        if "path" in context and context["path"] and isinstance(context["path"], str):
            payloads_to_scan.append(context["path"])

        max_payload_score = 0.0
        has_critical_payload = False

        for p in payloads_to_scan:
            scan_res = self.scan_payload(p)
            max_payload_score = max(max_payload_score, scan_res["threat_score"])
            if scan_res.get("highest_severity") == "critical":
                has_critical_payload = True

        scores.append(max_payload_score)
        weights.append(0.60)

        # 2. Evaluate Client IP
        ip_score = 0.0
        ip_is_malicious = False
        if "ip" in context and context["ip"]:
            ip_res = self.check_ip(str(context["ip"]))
            ip_score = ip_res["score"]
            ip_is_malicious = ip_res["is_malicious"]

        scores.append(ip_score)
        weights.append(0.25)

        # 3. Evaluate User-Agent
        ua_score = 0.0
        if "user_agent" in context and context["user_agent"]:
            ua_res = self.check_user_agent(str(context["user_agent"]))
            ua_score = ua_res["score"]

        scores.append(ua_score)
        weights.append(0.15)

        # Weighted calculation
        total_weight = sum(weights)
        weighted_average = sum(s * w for s, w in zip(scores, weights)) / total_weight

        # Guaranteed elevation for critical threat indicators
        # An injection or known C2 server must never be diluted by a benign User-Agent
        if has_critical_payload:
            final_score = max(weighted_average, 0.95, max_payload_score)
        elif ip_is_malicious and ip_score >= 0.85:
            final_score = max(weighted_average, 0.90, ip_score)
        else:
            final_score = max(weighted_average, max(scores) * 0.90)

        return round(float(min(1.0, max(0.0, final_score))), 4)


# ============================================================================
# Asynchronous Payload Scanner
# ============================================================================

class PayloadScanner:
    """
    Asynchronous payload inspection engine for Agentic AI Firewalls.

    Provides non-blocking execution, multi-encoding decoding chains
    (URL, Double URL, Base64, Hex), structural inspection, and actionable
    firewall recommendations ('allow', 'challenge', 'block').
    """

    def __init__(
        self,
        threat_db: Optional[ThreatIntelDB] = None,
        max_payload_size: int = 1_048_576,
        scan_timeout_seconds: float = 2.0,
    ):
        self.threat_db = threat_db or ThreatIntelDB()
        self.max_payload_size = max_payload_size
        self.scan_timeout_seconds = scan_timeout_seconds

    async def scan(
        self,
        payload: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Asynchronously scans a payload and returns comprehensive threat telemetry.

        Parameters:
            payload: The input payload string (e.g. request body, query parameter, prompt).
            context: Optional contextual parameters (e.g. {'ip': '...', 'user_agent': '...'}).

        Returns:
            A detailed analysis dictionary containing threat findings, composite risk score,
            and enforcement recommendation.
        """
        start_time = time.perf_counter()

        # Enforce maximum payload size to prevent ReDoS / memory exhaustion attacks
        if payload is not None and len(payload) > self.max_payload_size:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return {
                "status": "malicious",
                "threat_detected": True,
                "risk_score": 0.90,
                "action_recommendation": "block",
                "categories": ["payload_size_limit_exceeded"],
                "matches": [{
                    "category": "anomaly",
                    "pattern": "MAX_PAYLOAD_SIZE",
                    "matched_text": f"Payload length {len(payload)} exceeds limit of {self.max_payload_size}",
                    "position": (0, len(payload)),
                    "severity": "critical",
                    "source_variant": "raw",
                }],
                "total_matches": 1,
                "summary": "Payload blocked: Maximum allowable payload size exceeded.",
                "context_evaluation": {},
                "scan_metadata": {
                    "payload_length": len(payload),
                    "execution_time_ms": round(duration_ms, 3),
                    "decoded_variations_analyzed": 0,
                },
            }

        # Run CPU-bound regex scans and decoding in worker thread
        loop = asyncio.get_running_loop()
        try:
            analysis = await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_deep_scan, payload, context),
                timeout=self.scan_timeout_seconds,
            )
        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.warning("Payload scan timed out after %s seconds", self.scan_timeout_seconds)
            return {
                "status": "suspicious",
                "threat_detected": True,
                "risk_score": 0.75,
                "action_recommendation": "challenge",
                "categories": ["scan_timeout"],
                "matches": [],
                "total_matches": 0,
                "summary": "Scan exceeded configured processing timeout; potential ReDoS complexity attack.",
                "context_evaluation": {},
                "scan_metadata": {
                    "payload_length": len(payload) if payload else 0,
                    "execution_time_ms": round(duration_ms, 3),
                    "decoded_variations_analyzed": 0,
                },
            }

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        analysis["scan_metadata"]["execution_time_ms"] = round(duration_ms, 3)
        return analysis

    def _sync_deep_scan(
        self,
        payload: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Synchronous worker method performing decoding chain analysis,
        signature matching, and scoring.
        """
        text = payload if payload is not None else ""
        ctx = dict(context) if context else {}

        # 1. Base scan of the primary payload
        base_result = self.threat_db.scan_payload(text)

        all_matches: List[Dict[str, Any]] = list(base_result["matches"])
        detected_categories: Set[str] = set(base_result["categories_detected"])
        variations_analyzed = 1

        # 2. Inspect embedded Base64-encoded segments
        base64_candidates = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
        for candidate in base64_candidates[:5]:  # limit to top 5 candidates to prevent abuse
            try:
                decoded_bytes = base64.b64decode(candidate, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                if decoded_str and any(c.isalnum() for c in decoded_str):
                    variations_analyzed += 1
                    b64_scan = self.threat_db.scan_payload(decoded_str)
                    if b64_scan["is_threat"]:
                        for m in b64_scan["matches"]:
                            m["source_variant"] = "base64_decoded"
                            all_matches.append(m)
                            detected_categories.add(m["category"])
            except (binascii.Error, ValueError):
                continue

        # 3. Merge contextual checks
        context_eval: Dict[str, Any] = {}
        if "ip" in ctx and ctx["ip"]:
            context_eval["ip_check"] = self.threat_db.check_ip(str(ctx["ip"]))
        if "user_agent" in ctx and ctx["user_agent"]:
            context_eval["ua_check"] = self.threat_db.check_user_agent(str(ctx["user_agent"]))

        # Add payload to context to compute composite threat score
        ctx["payload"] = text
        composite_score = self.threat_db.get_threat_score(ctx)

        # 4. Determine Enforcement Classification
        has_critical = any(m.get("severity") == "critical" for m in all_matches)

        if composite_score >= 0.70 or has_critical:
            status = "malicious"
            recommendation = "block"
        elif composite_score >= 0.40 or len(all_matches) > 0:
            status = "suspicious"
            recommendation = "challenge"
        else:
            status = "clean"
            recommendation = "allow"

        # 5. Build Human/Agent-Readable Summary
        if all_matches:
            cats = ", ".join(sorted(list(detected_categories)))
            summary = (
                f"Threat detected: {status.upper()} payload matched categories [{cats}]. "
                f"Total indicators: {len(all_matches)}. Recommendation: {recommendation.upper()}."
            )
        else:
            summary = f"Payload analyzed as CLEAN. Recommendation: {recommendation.upper()}."

        return {
            "status": status,
            "threat_detected": len(all_matches) > 0 or status == "malicious",
            "risk_score": composite_score,
            "action_recommendation": recommendation,
            "categories": sorted(list(detected_categories)),
            "matches": all_matches,
            "total_matches": len(all_matches),
            "summary": summary,
            "context_evaluation": context_eval,
            "scan_metadata": {
                "payload_length": len(text),
                "execution_time_ms": 0.0,  # set by caller
                "decoded_variations_analyzed": variations_analyzed,
            },
        }
