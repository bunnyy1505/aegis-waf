import asyncio
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
import ipaddress
import json
import math
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import unquote, urlparse


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    frequencies = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def normalize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Normalizes header keys to lowercase strings for case-insensitive lookup."""
    if not headers or not isinstance(headers, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in headers.items()}


def extract_client_ip(request_context: Dict[str, Any]) -> str:
    """Extracts client IP from request context or proxy forwarding headers."""
    if "client_ip" in request_context and request_context["client_ip"]:
        return str(request_context["client_ip"]).strip()
    headers = normalize_headers(request_context.get("headers"))
    if "x-forwarded-for" in headers:
        return headers["x-forwarded-for"].split(",")[0].strip()
    if "x-real-ip" in headers:
        return headers["x-real-ip"].strip()
    return "127.0.0.1"


# =====================================================================
# 1. ThreatAnalyzerAgent
# =====================================================================

@dataclass
class ThreatAnalyzerConfig:
    """Configuration for ThreatAnalyzerAgent heuristics and thresholds."""
    block_threshold: float = 0.70
    sqli_weight: float = 0.85
    xss_weight: float = 0.80
    path_traversal_weight: float = 0.90
    cmd_injection_weight: float = 0.95
    csrf_weight: float = 0.70
    entropy_threshold: float = 4.8
    dangerous_char_threshold: float = 0.15


class ThreatAnalyzerAgent:
    """
    Analyzes incoming HTTP requests using rule-based heuristics and AI scoring.
    Detects SQLi, XSS, path traversal, command injection, and CSRF attempts.
    """

    def __init__(self, config: Optional[ThreatAnalyzerConfig] = None) -> None:
        self.config = config or ThreatAnalyzerConfig()
        self._init_rules()

    def _init_rules(self) -> None:
        flags = re.IGNORECASE | re.MULTILINE

        self.sqli_patterns = [
            (re.compile(r"(\b(UNION(\s+ALL)?)\b\s+SELECT\b)", flags), "SQLi: UNION SELECT statement"),
            (re.compile(r"(\bOR\b\s+['\"]?[\w\d]+['\"]?\s*=\s*['\"]?[\w\d]+['\"])", flags), "SQLi: Tautology OR clause"),
            (re.compile(r"(\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY)\s*\(\s*\d+\s*\))", flags), "SQLi: Time-based blind injection"),
            (re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE|WHERE)\b)", flags), "SQLi: DML/DDL query pattern"),
            (re.compile(r"(--|#|/\*.*?\*/|;\s*$)", flags), "SQLi: Comment or stacked query delimiter"),
            (re.compile(r"(\bEXEC(\s+|\+)+(xp_|sp_)\w+)", flags), "SQLi: Stored procedure execution"),
            (re.compile(r"('\s*OR\s*'1'\s*=\s*'1|1\s*=\s*1|'\s*OR\s*1\s*=\s*1)", flags), "SQLi: Boolean authentication bypass"),
        ]

        self.xss_patterns = [
            (re.compile(r"(<script\b[^>]*>[\s\S]*?<\/script>)", flags), "XSS: Script tag injection"),
            (re.compile(r"(javascript\s*:\s*[^\s\"'>]+)", flags), "XSS: Javascript pseudo-protocol"),
            (re.compile(r"(\bon(error|load|click|mouseover|submit|focus|blur|change|input)\s*=)", flags), "XSS: Inline HTML event handler"),
            (re.compile(r"(<\s*(img|svg|iframe|body|object|embed|link|meta)\b[^>]*\bon\w+\s*=)", flags), "XSS: Dangerous HTML tag with event attribute"),
            (re.compile(r"(\b(document\.(cookie|location|write|referrer)|window\.location)\b)", flags), "XSS: DOM access property tampering"),
            (re.compile(r"(\b(eval|alert|prompt|confirm)\s*\([^)]*\))", flags), "XSS: Arbitrary execution sink"),
        ]

        self.path_traversal_patterns = [
            (re.compile(r"(\.\.[/\\])", flags), "Path Traversal: Directory traversal dots (../)"),
            (re.compile(r"(%2e%2e[%2f%5c])", flags), "Path Traversal: URL-encoded traversal sequence"),
            (re.compile(r"(/etc/(passwd|shadow|group|hosts|issue))", flags), "Path Traversal: Sensitive POSIX system file target"),
            (re.compile(r"([a-zA-Z]:[\/\\]windows[\/\\](win\.ini|system32))", flags), "Path Traversal: Sensitive Windows system file target"),
            (re.compile(r"(%00|\\0)", flags), "Path Traversal: Null-byte injection bypass attempt"),
            (re.compile(r"(\b(WEB-INF|META-INF)[\/\\])", flags), "Path Traversal: Application internal configuration exposure"),
        ]

        self.cmd_injection_patterns = [
            (re.compile(r"([;&|`$]\s*(?:cat|ls|id|whoami|uname|netcat|nc|ncat|bash|sh|zsh|curl|wget|powershell|cmd\.exe)\b)", flags), "Command Injection: Chained shell command invocation"),
            (re.compile(r"(\$\([^\)]+\)|\`[^\`]+\`)", flags), "Command Injection: Shell command substitution syntax"),
            (re.compile(r"(\|\s*(?:bash|sh|powershell)\b)", flags), "Command Injection: Pipe into interpreter shell"),
            (re.compile(r"(\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\()", flags), "Command Injection: Backend execution function sink"),
            (re.compile(r"(\b(nc|netcat)\s+-[elp\d\s]+\b)", flags), "Command Injection: Netcat reverse/bind shell invocation"),
        ]

    def _extract_payloads(self, request_context: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extracts and normalizes string payloads from path, query params, headers, and body."""
        payloads: List[Tuple[str, str]] = []

        path = request_context.get("path", "")
        if path:
            payloads.append(("path", unquote(str(path))))

        query_params = request_context.get("query_params")
        if isinstance(query_params, dict):
            for k, v in query_params.items():
                payloads.append((f"query_param:{k}", unquote(str(v))))
        elif isinstance(query_params, str) and query_params:
            payloads.append(("query_string", unquote(query_params)))

        headers = normalize_headers(request_context.get("headers"))
        sensitive_header_keys = {"referer", "user-agent", "cookie", "authorization", "x-forwarded-for"}
        for k, v in headers.items():
            if k in sensitive_header_keys or k.startswith("x-"):
                payloads.append((f"header:{k}", unquote(v)))

        body = request_context.get("body", "")
        if isinstance(body, (dict, list)):
            payloads.append(("body", json.dumps(body)))
        elif isinstance(body, bytes):
            try:
                payloads.append(("body", body.decode("utf-8", errors="ignore")))
            except Exception:
                pass
        elif isinstance(body, str) and body:
            payloads.append(("body", unquote(body)))

        return payloads

    def _evaluate_csrf(self, request_context: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Evaluates CSRF risk on state-changing requests."""
        method = str(request_context.get("method", "GET")).upper()
        if method in {"GET", "HEAD", "OPTIONS"}:
            return 0.0, []

        headers = normalize_headers(request_context.get("headers"))
        flags: List[str] = []

        # Check for CSRF verification tokens in headers and body
        csrf_tokens = [
            headers.get("x-csrf-token"),
            headers.get("x-xsrf-token"),
            headers.get("csrf-token"),
        ]
        body = request_context.get("body")
        if isinstance(body, dict):
            csrf_tokens.append(body.get("csrf_token") or body.get("_csrf"))
        elif isinstance(body, str) and ("csrf_token=" in body or "_csrf=" in body):
            csrf_tokens.append("present_in_body")

        has_csrf_token = any(tok for tok in csrf_tokens)

        # Origin / Referer validation against Host
        host = headers.get("host")
        origin = headers.get("origin")
        referer = headers.get("referer")

        origin_mismatch = False
        if origin and host:
            parsed_origin = urlparse(origin)
            if parsed_origin.netloc and parsed_origin.netloc.lower() != host.lower():
                origin_mismatch = True
                flags.append(f"Origin header mismatch: '{parsed_origin.netloc}' != '{host}'")

        if referer and host and not origin_mismatch:
            parsed_referer = urlparse(referer)
            if parsed_referer.netloc and parsed_referer.netloc.lower() != host.lower():
                origin_mismatch = True
                flags.append(f"Referer header mismatch: '{parsed_referer.netloc}' != '{host}'")

        sec_fetch_site = headers.get("sec-fetch-site")
        is_cross_site = sec_fetch_site == "cross-site"
        if is_cross_site:
            flags.append("Sec-Fetch-Site indicates untrusted cross-site request context")

        has_auth_bearer = "authorization" in headers and "bearer" in headers["authorization"].lower()

        if origin_mismatch:
            return self.config.csrf_weight, flags
        if is_cross_site and not has_csrf_token:
            return self.config.csrf_weight, flags
        if not has_csrf_token and not has_auth_bearer:
            flags.append(f"State-changing {method} request missing CSRF protection token")
            return self.config.csrf_weight * 0.8, flags

        return 0.0, []

    def _calculate_ai_heuristic_score(self, payloads: List[Tuple[str, str]]) -> Tuple[float, Dict[str, Any]]:
        """Simulates AI scoring based on text entropy and dangerous character density."""
        if not payloads:
            return 0.0, {}

        dangerous_chars = set("'\"<>;&|`$\\(){}[]/%*^=")
        max_entropy = 0.0
        max_density = 0.0
        details: Dict[str, Any] = {}

        for source, text in payloads:
            if not text or len(text) < 4:
                continue
            entropy = calculate_entropy(text)
            char_count = len(text)
            danger_count = sum(1 for ch in text if ch in dangerous_chars)
            density = danger_count / char_count

            if entropy > max_entropy:
                max_entropy = entropy
                details["max_entropy_source"] = source
            if density > max_density:
                max_density = density
                details["max_density_source"] = source

        details["max_entropy"] = round(max_entropy, 3)
        details["max_dangerous_char_density"] = round(max_density, 3)

        ai_score = 0.0
        if max_entropy > self.config.entropy_threshold:
            ai_score += 0.35 * min(1.0, (max_entropy - self.config.entropy_threshold) / 2.0)
        if max_density > self.config.dangerous_char_threshold:
            ai_score += 0.50 * min(1.0, (max_density - self.config.dangerous_char_threshold) / 0.3)

        return min(1.0, ai_score), details

    async def analyze(self, request_context: dict) -> dict:
        """
        Analyzes incoming HTTP request for threats.
        Returns: {"score": float, "blocked": bool, "reason": str, "details": dict}
        """
        payloads = self._extract_payloads(request_context)
        detected_threats: List[str] = []
        rule_matches: List[Dict[str, str]] = []
        matched_weights: List[float] = []

        categories = [
            ("SQLi", self.sqli_patterns, self.config.sqli_weight),
            ("XSS", self.xss_patterns, self.config.xss_weight),
            ("PathTraversal", self.path_traversal_patterns, self.config.path_traversal_weight),
            ("CommandInjection", self.cmd_injection_patterns, self.config.cmd_injection_weight),
        ]

        for source, text in payloads:
            for cat_name, patterns, weight in categories:
                for regex, rule_desc in patterns:
                    match = regex.search(text)
                    if match:
                        snippet = match.group(0)[:80]
                        rule_matches.append({
                            "category": cat_name,
                            "rule": rule_desc,
                            "source": source,
                            "snippet": snippet
                        })
                        detected_threats.append(f"{cat_name} in {source}")
                        matched_weights.append(weight)

        csrf_score, csrf_reasons = self._evaluate_csrf(request_context)
        if csrf_score > 0:
            matched_weights.append(csrf_score)
            for r in csrf_reasons:
                detected_threats.append(f"CSRF: {r}")
                rule_matches.append({"category": "CSRF", "rule": r, "source": "request_context", "snippet": ""})

        if matched_weights:
            rule_score = 1.0 - math.prod(1.0 - min(w, 0.99) for w in matched_weights)
        else:
            rule_score = 0.0

        ai_score, ai_details = self._calculate_ai_heuristic_score(payloads)

        if rule_score > 0:
            final_score = min(1.0, max(rule_score, rule_score * 0.75 + ai_score * 0.25))
        else:
            final_score = round(ai_score * 0.5, 3)

        blocked = final_score >= self.config.block_threshold
        if blocked:
            primary_threat = detected_threats[0] if detected_threats else "Heuristic anomaly score exceeded threshold"
            reason = f"Security threat detected: {primary_threat}"
        else:
            reason = "No security threat detected"

        return {
            "score": round(float(final_score), 4),
            "blocked": bool(blocked),
            "reason": str(reason),
            "details": {
                "detected_threats": detected_threats,
                "rule_matches": rule_matches,
                "ai_score": round(float(ai_score), 4),
                "ai_features": ai_details,
                "payloads_inspected_count": len(payloads),
            }
        }


# =====================================================================
# 2. RateLimiterAgent
# =====================================================================

@dataclass
class RateLimiterConfig:
    """Configuration for RateLimiterAgent sliding window and thresholds."""
    window_seconds: float = 60.0
    max_requests: int = 100
    burst_limit: int = 25
    block_duration_seconds: float = 300.0
    key_strategy: str = "ip"  # "ip", "user", or "ip_endpoint"


class RateLimiterAgent:
    """
    Tracks request rates per IP/user/endpoint using a sliding window algorithm.
    Returns rate violation status and block decision.
    """

    def __init__(self, config: Optional[RateLimiterConfig] = None) -> None:
        self.config = config or RateLimiterConfig()
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._banned_until: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    def _resolve_key(self, request_context: Dict[str, Any]) -> str:
        ip = extract_client_ip(request_context)
        if self.config.key_strategy == "user":
            user_id = request_context.get("user_id")
            return f"user:{user_id}" if user_id else f"ip:{ip}"
        if self.config.key_strategy == "ip_endpoint":
            method = request_context.get("method", "GET").upper()
            path = request_context.get("path", "/")
            return f"{ip}:{method}:{path}"
        return f"ip:{ip}"

    async def analyze(self, request_context: dict) -> dict:
        """
        Evaluates request rate for the client against sliding window limits.
        Returns: {"score": float, "blocked": bool, "reason": str, "details": dict}
        """
        key = self._resolve_key(request_context)
        now = float(request_context.get("timestamp", time.time()))

        async with self._lock:
            # Check existing temporary ban
            if key in self._banned_until:
                ban_end = self._banned_until[key]
                if now < ban_end:
                    remaining = ban_end - now
                    return {
                        "score": 1.0,
                        "blocked": True,
                        "reason": f"Client temporarily banned due to rate limit violation ({remaining:.1f}s remaining)",
                        "details": {
                            "key": key,
                            "banned": True,
                            "remaining_ban_seconds": round(remaining, 1),
                            "window_seconds": self.config.window_seconds,
                            "limit": self.config.max_requests
                        }
                    }
                else:
                    del self._banned_until[key]

            # Evict timestamps outside sliding window
            timestamps = self._requests[key]
            window_cutoff = now - self.config.window_seconds
            while timestamps and timestamps[0] <= window_cutoff:
                timestamps.popleft()

            # Burst rate evaluation (last 1 second)
            burst_cutoff = now - 1.0
            burst_count = sum(1 for t in timestamps if t > burst_cutoff)

            # Record current request
            timestamps.append(now)
            current_window_count = len(timestamps)

            is_window_exceeded = current_window_count > self.config.max_requests
            is_burst_exceeded = (burst_count + 1) > self.config.burst_limit

            if is_window_exceeded or is_burst_exceeded:
                self._banned_until[key] = now + self.config.block_duration_seconds
                score = 1.0
                blocked = True
                if is_burst_exceeded:
                    reason = f"Burst limit exceeded: {burst_count + 1} req/s (max {self.config.burst_limit})"
                else:
                    reason = f"Rate limit exceeded: {current_window_count} req/{self.config.window_seconds}s (max {self.config.max_requests})"
            else:
                score = min(1.0, current_window_count / max(1, self.config.max_requests))
                blocked = False
                reason = "Request rate within permitted threshold"

            return {
                "score": round(float(score), 4),
                "blocked": bool(blocked),
                "reason": str(reason),
                "details": {
                    "key": key,
                    "current_window_count": current_window_count,
                    "max_requests": self.config.max_requests,
                    "burst_count": burst_count + 1,
                    "burst_limit": self.config.burst_limit,
                    "window_seconds": self.config.window_seconds,
                    "banned": blocked
                }
            }


# =====================================================================
# 3. AnomalyDetectorAgent
# =====================================================================

@dataclass
class RunningStat:
    """Tracks running mean and variance using Welford's algorithm."""
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / self.count if self.count > 1 else 0.0

    @property
    def stddev(self) -> float:
        return math.sqrt(self.variance)


@dataclass
class AnomalyDetectorConfig:
    """Configuration for AnomalyDetectorAgent statistical baselines."""
    min_samples: int = 25
    z_score_threshold: float = 3.0
    score_threshold: float = 0.75
    features: List[str] = field(default_factory=lambda: [
        "content_length",
        "header_count",
        "path_length",
        "path_depth",
        "param_count",
        "payload_entropy"
    ])


class AnomalyDetectorAgent:
    """
    Uses statistical baseline tracking (mean and standard deviation of request patterns)
    to detect behavioral and structural anomalies.
    """

    def __init__(self, config: Optional[AnomalyDetectorConfig] = None) -> None:
        self.config = config or AnomalyDetectorConfig()
        self._stats: Dict[str, RunningStat] = {
            feature: RunningStat() for feature in self.config.features
        }
        self._lock = asyncio.Lock()

    def _extract_features(self, request_context: Dict[str, Any]) -> Dict[str, float]:
        path = str(request_context.get("path", "/"))
        headers = request_context.get("headers", {})
        query_params = request_context.get("query_params", {})
        body = request_context.get("body", "")

        if isinstance(body, (dict, list)):
            body_str = json.dumps(body)
        elif isinstance(body, bytes):
            body_str = body.decode("utf-8", errors="ignore")
        else:
            body_str = str(body or "")

        content_length = float(len(body_str.encode("utf-8")))
        header_count = float(len(headers) if isinstance(headers, dict) else 0)
        path_length = float(len(path))
        path_depth = float(path.strip("/").count("/") + 1 if path.strip("/") else 0)
        param_count = float(len(query_params) if isinstance(query_params, dict) else 0)
        payload_entropy = calculate_entropy(path + body_str)

        return {
            "content_length": content_length,
            "header_count": header_count,
            "path_length": path_length,
            "path_depth": path_depth,
            "param_count": param_count,
            "payload_entropy": payload_entropy
        }

    async def analyze(self, request_context: dict) -> dict:
        """
        Compares incoming request features to running statistical baseline.
        Returns: {"score": float, "blocked": bool, "reason": str, "details": dict}
        """
        features = self._extract_features(request_context)

        async with self._lock:
            min_count = min(self._stats[f].count for f in self.config.features)
            warmed_up = min_count >= self.config.min_samples

            z_scores: Dict[str, float] = {}
            max_z = 0.0
            anomaly_feature = ""

            for feature_name, value in features.items():
                stat = self._stats[feature_name]
                if warmed_up:
                    sigma = max(stat.stddev, 0.001)
                    z = abs(value - stat.mean) / sigma
                    z_scores[feature_name] = round(z, 2)
                    if z > max_z:
                        max_z = z
                        anomaly_feature = feature_name
                else:
                    z_scores[feature_name] = 0.0

            if not warmed_up:
                # Update baseline during initial warmup
                for feature_name, value in features.items():
                    self._stats[feature_name].update(value)

                return {
                    "score": 0.0,
                    "blocked": False,
                    "reason": f"Statistical baseline training in progress ({min_count}/{self.config.min_samples} samples)",
                    "details": {
                        "warmed_up": False,
                        "samples_collected": min_count,
                        "features": features
                    }
                }

            normalized_score = min(1.0, max_z / (self.config.z_score_threshold * 1.5))
            is_anomaly = max_z >= self.config.z_score_threshold
            blocked = is_anomaly and (normalized_score >= self.config.score_threshold)

            if blocked:
                reason = f"Statistical anomaly detected in '{anomaly_feature}' (Z-score: {max_z:.2f} >= {self.config.z_score_threshold})"
            elif is_anomaly:
                reason = f"Elevated anomaly variance in '{anomaly_feature}' (Z-score: {max_z:.2f})"
            else:
                reason = "Request metrics conform to baseline distribution"

            # Update baseline only for non-blocked requests to avoid poisoning the baseline
            if not blocked:
                for feature_name, value in features.items():
                    self._stats[feature_name].update(value)

            feature_summary = {
                f: {
                    "value": round(features[f], 2),
                    "mean": round(self._stats[f].mean, 2),
                    "stddev": round(self._stats[f].stddev, 2),
                    "z_score": z_scores.get(f, 0.0)
                }
                for f in self.config.features
            }

            return {
                "score": round(float(normalized_score), 4),
                "blocked": bool(blocked),
                "reason": str(reason),
                "details": {
                    "warmed_up": True,
                    "max_z_score": round(max_z, 2),
                    "anomalous_feature": anomaly_feature if is_anomaly else None,
                    "feature_analysis": feature_summary
                }
            }


# =====================================================================
# 4. GeoBlockAgent
# =====================================================================

@dataclass
class GeoBlockConfig:
    """Configuration for GeoBlockAgent."""
    blocked_countries: Set[str] = field(default_factory=lambda: {"KP", "IR", "SY", "CU"})
    high_risk_countries: Dict[str, float] = field(default_factory=lambda: {
        "RU": 0.65,
        "CN": 0.50,
        "BY": 0.60,
        "T1": 0.85
    })
    allow_private_ips: bool = True
    default_country: str = "US"
    ip_lookup_table: Optional[Dict[str, Dict[str, Any]]] = None


class GeoBlockAgent:
    """
    Checks IP geo-data against a local subnet lookup table and blocks banned
    or high-risk countries and regions.
    """

    _DEFAULT_GEO_DB: Dict[str, Dict[str, Any]] = {
        # Loopback & Private subnets
        "127.0.0.0/8": {"country": "LOCAL", "country_name": "Loopback", "region": "Host", "is_private": True},
        "10.0.0.0/8": {"country": "LOCAL", "country_name": "Private Network", "region": "LAN", "is_private": True},
        "172.16.0.0/12": {"country": "LOCAL", "country_name": "Private Network", "region": "LAN", "is_private": True},
        "192.168.0.0/16": {"country": "LOCAL", "country_name": "Private Network", "region": "LAN", "is_private": True},
        "::1/128": {"country": "LOCAL", "country_name": "IPv6 Loopback", "region": "Host", "is_private": True},
        "fc00::/7": {"country": "LOCAL", "country_name": "IPv6 Unique Local", "region": "LAN", "is_private": True},

        # Sample regional ranges (North Korea, Iran, Syria, Cuba, Russia, China, Tor, etc.)
        "175.45.176.0/22": {"country": "KP", "country_name": "North Korea", "region": "Pyongyang", "is_private": False},
        "210.52.109.0/24": {"country": "KP", "country_name": "North Korea", "region": "Ryugyong", "is_private": False},
        "5.120.0.0/13": {"country": "IR", "country_name": "Iran", "region": "Tehran", "is_private": False},
        "82.165.197.0/24": {"country": "SY", "country_name": "Syria", "region": "Damascus", "is_private": False},
        "152.206.0.0/15": {"country": "CU", "country_name": "Cuba", "region": "Havana", "is_private": False},
        "95.173.136.0/21": {"country": "RU", "country_name": "Russia", "region": "Moscow", "is_private": False},
        "185.158.248.0/22": {"country": "RU", "country_name": "Russia", "region": "St. Petersburg", "is_private": False},
        "202.108.22.0/24": {"country": "CN", "country_name": "China", "region": "Beijing", "is_private": False},
        "178.172.160.0/20": {"country": "BY", "country_name": "Belarus", "region": "Minsk", "is_private": False},
        "185.220.101.0/24": {"country": "T1", "country_name": "Tor Exit Node", "region": "Anonymous Proxy", "is_private": False},

        # Permitted sample ranges (US, UK, Australia, etc.)
        "8.8.8.0/24": {"country": "US", "country_name": "United States", "region": "California", "is_private": False},
        "142.250.0.0/15": {"country": "US", "country_name": "United States", "region": "Mountain View", "is_private": False},
        "212.58.244.0/22": {"country": "GB", "country_name": "United Kingdom", "region": "London", "is_private": False},
        "1.1.1.0/24": {"country": "AU", "country_name": "Australia", "region": "Sydney", "is_private": False},
    }

    def __init__(self, config: Optional[GeoBlockConfig] = None) -> None:
        self.config = config or GeoBlockConfig()
        raw_db = self.config.ip_lookup_table or self._DEFAULT_GEO_DB
        self._compiled_networks: List[Tuple[Any, Dict[str, Any]]] = []
        for cidr, metadata in raw_db.items():
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self._compiled_networks.append((network, metadata))
            except ValueError:
                continue

    def _lookup_ip(self, ip_str: str) -> Dict[str, Any]:
        """Resolves IP metadata by matching against compiled network CIDRs."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return {
                "country": self.config.default_country,
                "country_name": "Unknown",
                "region": "Unknown",
                "is_private": False,
                "matched_subnet": None
            }

        for network, meta in self._compiled_networks:
            if ip_obj in network:
                result = dict(meta)
                result["matched_subnet"] = str(network)
                return result

        is_private = ip_obj.is_private or ip_obj.is_loopback
        return {
            "country": "LOCAL" if is_private else self.config.default_country,
            "country_name": "Private/Local Network" if is_private else "Global IP",
            "region": "Default",
            "is_private": is_private,
            "matched_subnet": None
        }

    async def analyze(self, request_context: dict) -> dict:
        """
        Evaluates geolocation of the client IP.
        Returns: {"score": float, "blocked": bool, "reason": str, "details": dict}
        """
        ip = extract_client_ip(request_context)
        geo_info = self._lookup_ip(ip)

        country = geo_info.get("country", self.config.default_country).upper()
        country_name = geo_info.get("country_name", "Unknown")
        is_private = geo_info.get("is_private", False)

        if is_private:
            if self.config.allow_private_ips:
                return {
                    "score": 0.0,
                    "blocked": False,
                    "reason": "Private/local network IP address allowed",
                    "details": {"client_ip": ip, **geo_info}
                }
            else:
                return {
                    "score": 1.0,
                    "blocked": True,
                    "reason": "Direct access from private/unroutable IP addresses is blocked",
                    "details": {"client_ip": ip, **geo_info}
                }

        if country in self.config.blocked_countries:
            return {
                "score": 1.0,
                "blocked": True,
                "reason": f"Access denied: IP originates from banned country/territory {country_name} ({country})",
                "details": {"client_ip": ip, **geo_info}
            }

        if country in self.config.high_risk_countries:
            risk_score = self.config.high_risk_countries[country]
            blocked = risk_score >= 0.8
            return {
                "score": round(float(risk_score), 4),
                "blocked": bool(blocked),
                "reason": f"Elevated geographic risk: connection from {country_name} ({country})",
                "details": {"client_ip": ip, "risk_tier": "high", **geo_info}
            }

        return {
            "score": 0.0,
            "blocked": False,
            "reason": f"Origin location permitted: {country_name} ({country})",
            "details": {"client_ip": ip, **geo_info}
        }


# =====================================================================
# 5. BotDetectorAgent
# =====================================================================

@dataclass
class BotDetectorConfig:
    """Configuration for BotDetectorAgent."""
    bot_score_threshold: float = 0.70
    min_request_interval_ms: float = 40.0
    cadence_variance_threshold: float = 0.04
    timing_history_size: int = 15
    inspect_browser_consistency: bool = True


class BotDetectorAgent:
    """
    Detects bots via User-Agent signature analysis, headless browser traits,
    and microsecond request timing/cadence patterns.
    """

    KNOWN_SCRAPERS_REGEX = re.compile(
        r"(curl|wget|python-requests|aiohttp|httpx|scrapy|sqlmap|nikto|"
        r"zgrab|masscan|go-http-client|apache-httpclient|java\/|postmanruntime|"
        r"insomnia|libwww-perl|urllib|grequests)",
        re.IGNORECASE
    )

    HEADLESS_SIGNATURES_REGEX = re.compile(
        r"(headlesschrome|phantomjs|selenium|puppeteer|playwright|nightwatch|cypress)",
        re.IGNORECASE
    )

    def __init__(self, config: Optional[BotDetectorConfig] = None) -> None:
        self.config = config or BotDetectorConfig()
        self._timing_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=self.config.timing_history_size)
        )
        self._lock = asyncio.Lock()

    def _inspect_user_agent(self, ua: str) -> Tuple[float, List[str]]:
        signals: List[str] = []
        score = 0.0

        if not ua:
            return 0.85, ["Missing or empty User-Agent header"]

        ua_clean = ua.strip()
        if len(ua_clean) < 8:
            signals.append(f"Suspiciously brief User-Agent: '{ua_clean}'")
            score += 0.50

        tool_match = self.KNOWN_SCRAPERS_REGEX.search(ua_clean)
        if tool_match:
            signals.append(f"Known automated client tool detected: {tool_match.group(0)}")
            score += 0.85

        headless_match = self.HEADLESS_SIGNATURES_REGEX.search(ua_clean)
        if headless_match:
            signals.append(f"Headless automation browser detected: {headless_match.group(0)}")
            score += 0.90

        return min(1.0, score), signals

    def _inspect_browser_consistency(self, ua: str, headers: Dict[str, str]) -> Tuple[float, List[str]]:
        if not self.config.inspect_browser_consistency or not ua:
            return 0.0, []

        signals: List[str] = []
        score = 0.0

        if "x-puppeteer" in headers or "x-selenium" in headers:
            signals.append("Explicit automation framework header present")
            score += 0.95

        is_chrome = "chrome" in ua.lower() and "safari" in ua.lower() and "edge" not in ua.lower()
        if is_chrome:
            has_sec_fetch = "sec-fetch-mode" in headers or "sec-fetch-site" in headers
            has_accept = "accept" in headers
            has_accept_encoding = "accept-encoding" in headers

            if not has_sec_fetch and not has_accept:
                signals.append("Claimed Chrome browser lacks standard Sec-Fetch and Accept headers")
                score += 0.45
            if not has_accept_encoding:
                signals.append("Browser client missing Accept-Encoding compression header")
                score += 0.30

        return min(1.0, score), signals

    def _evaluate_timing(self, ip: str, now: float) -> Tuple[float, List[str], Dict[str, Any]]:
        history = self._timing_history[ip]
        signals: List[str] = []
        score = 0.0
        metrics: Dict[str, Any] = {}

        if history:
            prev_time = history[-1]
            interval_ms = (now - prev_time) * 1000.0
            metrics["interval_ms"] = round(interval_ms, 2)

            if interval_ms < self.config.min_request_interval_ms:
                signals.append(f"Sub-human request interval ({interval_ms:.1f}ms < {self.config.min_request_interval_ms}ms)")
                score += 0.80

            if len(history) >= 5:
                intervals = [
                    (history[i] - history[i - 1]) * 1000.0
                    for i in range(1, len(history))
                ]
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
                stddev = math.sqrt(variance)
                cov = stddev / mean_interval if mean_interval > 0 else 1.0

                metrics["mean_interval_ms"] = round(mean_interval, 2)
                metrics["stddev_ms"] = round(stddev, 2)
                metrics["cov"] = round(cov, 4)

                if mean_interval < 5000.0 and cov < self.config.cadence_variance_threshold:
                    signals.append(f"Robotic fixed-cadence timing detected (COV {cov:.4f} < {self.config.cadence_variance_threshold})")
                    score += 0.85

        history.append(now)
        return min(1.0, score), signals, metrics

    async def analyze(self, request_context: dict) -> dict:
        """
        Analyzes request headers, user agent, and timing patterns for bot activity.
        Returns: {"score": float, "blocked": bool, "reason": str, "details": dict}
        """
        headers = normalize_headers(request_context.get("headers"))
        user_agent = headers.get("user-agent", "")
        ip = extract_client_ip(request_context)
        now = float(request_context.get("timestamp", time.time()))

        # 1. User-Agent Analysis
        ua_score, ua_signals = self._inspect_user_agent(user_agent)

        # 2. Browser Header Consistency
        header_score, header_signals = self._inspect_browser_consistency(user_agent, headers)

        # 3. Timing & Velocity Analysis (synchronized per IP)
        async with self._lock:
            timing_score, timing_signals, timing_metrics = self._evaluate_timing(ip, now)

        all_signals = ua_signals + header_signals + timing_signals
        max_component_score = max(ua_score, header_score, timing_score)
        compounded_score = max_component_score + (0.10 * (len(all_signals) - 1) if len(all_signals) > 1 else 0.0)
        final_score = min(1.0, compounded_score)

        blocked = final_score >= self.config.bot_score_threshold
        if blocked:
            reason = f"Automated bot signature detected: {all_signals[0]}"
        elif all_signals:
            reason = f"Suspicious automated activity: {all_signals[0]}"
        else:
            reason = "Human client characteristics verified"

        return {
            "score": round(float(final_score), 4),
            "blocked": bool(blocked),
            "reason": str(reason),
            "details": {
                "detected_signals": all_signals,
                "ua_score": round(float(ua_score), 4),
                "header_score": round(float(header_score), 4),
                "timing_score": round(float(timing_score), 4),
                "timing_metrics": timing_metrics,
                "user_agent": user_agent[:120] if user_agent else None
            }
        }


# =====================================================================
# Firewall Coordinator
# =====================================================================

@dataclass
class FirewallCoordinatorConfig:
    """Configuration for coordinating all core AI firewall agents."""
    overall_block_threshold: float = 0.70
    threat_weight: float = 0.35
    rate_weight: float = 0.20
    anomaly_weight: float = 0.15
    geo_weight: float = 0.15
    bot_weight: float = 0.15


class FirewallCoordinator:
    """
    Coordinates all core agents to inspect requests concurrently using asyncio.gather.
    Produces an aggregated defense verdict.
    """

    def __init__(
        self,
        config: Optional[FirewallCoordinatorConfig] = None,
        threat_analyzer: Optional[ThreatAnalyzerAgent] = None,
        rate_limiter: Optional[RateLimiterAgent] = None,
        anomaly_detector: Optional[AnomalyDetectorAgent] = None,
        geo_blocker: Optional[GeoBlockAgent] = None,
        bot_detector: Optional[BotDetectorAgent] = None,
    ) -> None:
        self.config = config or FirewallCoordinatorConfig()
        self.threat_analyzer = threat_analyzer or ThreatAnalyzerAgent()
        self.rate_limiter = rate_limiter or RateLimiterAgent()
        self.anomaly_detector = anomaly_detector or AnomalyDetectorAgent()
        self.geo_blocker = geo_blocker or GeoBlockAgent()
        self.bot_detector = bot_detector or BotDetectorAgent()

    async def evaluate_request(self, request_context: dict) -> dict:
        """
        Runs all core agents concurrently on the incoming request context.
        Returns aggregate block decision, overall risk score, and per-agent reports.
        """
        threat_res, rate_res, anomaly_res, geo_res, bot_res = await asyncio.gather(
            self.threat_analyzer.analyze(request_context),
            self.rate_limiter.analyze(request_context),
            self.anomaly_detector.analyze(request_context),
            self.geo_blocker.analyze(request_context),
            self.bot_detector.analyze(request_context),
        )

        agent_results = {
            "threat_analyzer": threat_res,
            "rate_limiter": rate_res,
            "anomaly_detector": anomaly_res,
            "geo_blocker": geo_res,
            "bot_detector": bot_res,
        }

        any_blocked = any(res["blocked"] for res in agent_results.values())
        blocking_agents = [name for name, res in agent_results.items() if res["blocked"]]

        weighted_score = (
            threat_res["score"] * self.config.threat_weight +
            rate_res["score"] * self.config.rate_weight +
            anomaly_res["score"] * self.config.anomaly_weight +
            geo_res["score"] * self.config.geo_weight +
            bot_res["score"] * self.config.bot_weight
        )

        overall_score = 1.0 if any_blocked else min(1.0, weighted_score)
        blocked = any_blocked or (overall_score >= self.config.overall_block_threshold)

        if blocked:
            if blocking_agents:
                first_agent = blocking_agents[0]
                reason = f"Request blocked by {first_agent}: {agent_results[first_agent]['reason']}"
            else:
                reason = f"Request blocked: aggregate risk score {overall_score:.2f} exceeded threshold"
        else:
            reason = "Request authorized: all security agents cleared"

        return {
            "score": round(float(overall_score), 4),
            "blocked": bool(blocked),
            "reason": str(reason),
            "details": {
                "blocking_agents": blocking_agents,
                "agent_results": agent_results
            }
        }
