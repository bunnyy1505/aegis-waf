import asyncio
import json
import math
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional, Set, Tuple, Union

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

# Enable auto mode compatibility for pytest-asyncio
pytestmark = pytest.mark.asyncio


# ============================================================================
# Core Domain Models & Agent Implementations
# ============================================================================

class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"


@dataclass
class RequestContext:
    client_ip: str = "127.0.0.1"
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    body: Any = ""
    timestamp: float = field(default_factory=time.time)

    def get_full_payload(self) -> str:
        parts = [self.path]
        for k, v in sorted(self.query_params.items()):
            parts.append(f"{k}={v}")
        for k, v in sorted(self.headers.items()):
            parts.append(f"{k}:{v}")
        if self.body:
            if isinstance(self.body, (dict, list)):
                parts.append(json.dumps(self.body, sort_keys=True))
            else:
                parts.append(str(self.body))
        return " ".join(parts)


class ThreatIntelDB:
    """Threat Intelligence Database scanning request payloads for malicious signatures."""

    def __init__(self):
        self.sql_patterns = [
            re.compile(r"('|\")\s*(OR|AND)\s+.*(=|<|>)", re.IGNORECASE),
            re.compile(r"\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO|DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM)\b", re.IGNORECASE),
            re.compile(r"(--|/\*|;\s*DROP|;\s*DELETE)", re.IGNORECASE),
            re.compile(r"\b(SLEEP\s*\(|BENCHMARK\s*\()", re.IGNORECASE),
        ]
        self.xss_patterns = [
            re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<[^>]*\b(onload|onerror|onclick|onmouseover)\s*=[^>]*>", re.IGNORECASE),
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"\b(alert|prompt|confirm)\s*\(", re.IGNORECASE),
            re.compile(r"\bdocument\.cookie\b", re.IGNORECASE),
        ]
        self.traversal_patterns = [
            re.compile(r"(\.\.[/\\]|%2e%2e[%2f/\\])", re.IGNORECASE),
            re.compile(r"(etc/(passwd|shadow)|windows/(win\.ini|system32)|boot\.ini)", re.IGNORECASE),
        ]
        self.cmdi_patterns = [
            re.compile(r"[;&|`$]\s*(cat|ls|rm|id|whoami|nc|sh|bash|curl|wget|ping)\b", re.IGNORECASE),
            re.compile(r"\$\([^\)]+\)", re.IGNORECASE),
            re.compile(r"`[^`]+`", re.IGNORECASE),
        ]

    async def is_sql_injection(self, text: str) -> bool:
        return any(p.search(text) for p in self.sql_patterns)

    async def is_xss(self, text: str) -> bool:
        return any(p.search(text) for p in self.xss_patterns)

    async def is_path_traversal(self, text: str) -> bool:
        return any(p.search(text) for p in self.traversal_patterns)

    async def is_command_injection(self, text: str) -> bool:
        return any(p.search(text) for p in self.cmdi_patterns)

    async def detect_threat(self, payload: str) -> Optional[str]:
        if await self.is_sql_injection(payload):
            return "sql_injection"
        if await self.is_xss(payload):
            return "xss"
        if await self.is_path_traversal(payload):
            return "path_traversal"
        if await self.is_command_injection(payload):
            return "command_injection"
        return None

    async def check_threat(self, payload: str) -> Dict[str, Any]:
        threats = []
        if await self.is_sql_injection(payload):
            threats.append("sql_injection")
        if await self.is_xss(payload):
            threats.append("xss")
        if await self.is_path_traversal(payload):
            threats.append("path_traversal")
        if await self.is_command_injection(payload):
            threats.append("command_injection")
        return {
            "is_threat": len(threats) > 0,
            "threats": threats,
            "primary_threat": threats[0] if threats else None,
        }


class RateLimiterAgent:
    """Agent monitoring request velocity and enforcing sliding-window rate limiting per IP."""

    def __init__(self, threshold: int = 5, window_seconds: float = 60.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.records: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def is_rate_limited(self, client_id: str) -> bool:
        async with self._lock:
            now = time.time()
            timestamps = self.records.get(client_id, [])
            cutoff = now - self.window_seconds
            timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(timestamps) >= self.threshold:
                self.records[client_id] = timestamps
                return True

            timestamps.append(now)
            self.records[client_id] = timestamps
            return False

    async def get_remaining_capacity(self, client_id: str) -> int:
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            timestamps = [ts for ts in self.records.get(client_id, []) if ts > cutoff]
            return max(0, self.threshold - len(timestamps))

    async def reset(self, client_id: Optional[str] = None):
        async with self._lock:
            if client_id:
                self.records.pop(client_id, None)
            else:
                self.records.clear()

    async def evaluate(self, context: RequestContext) -> Dict[str, Any]:
        limited = await self.is_rate_limited(context.client_ip)
        remaining = await self.get_remaining_capacity(context.client_ip)
        return {
            "limited": limited,
            "remaining": remaining,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
        }


@dataclass
class ThreatAnalysisResult:
    score: float
    threat_level: str
    threats_detected: List[str]
    reasons: List[str]
    is_malicious: bool


class ThreatAnalyzerAgent:
    """Agent analyzing request contexts and generating composite threat scores."""

    def __init__(
        self,
        threat_intel_db: Optional[ThreatIntelDB] = None,
        high_threshold: float = 0.8,
        medium_threshold: float = 0.5,
    ):
        self.db = threat_intel_db or ThreatIntelDB()
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

    async def analyze(self, context: Union[RequestContext, str]) -> ThreatAnalysisResult:
        if isinstance(context, RequestContext):
            payload = context.get_full_payload()
        else:
            payload = str(context)

        threat_info = await self.db.check_threat(payload)
        threats = threat_info["threats"]

        if threats:
            base_score = 0.85 + min(0.15, 0.05 * (len(threats) - 1))
            score = round(base_score, 3)
            threat_level = "CRITICAL" if score >= 0.9 else "HIGH"
            is_malicious = True
            reasons = [f"Detected {t}" for t in threats]
        else:
            suspicious_chars = ["'", '"', ";", "--", "<", ">", "../", "$"]
            suspicion_count = sum(payload.count(c) for c in suspicious_chars)
            if suspicion_count >= 5:
                score = 0.55
                threat_level = "MEDIUM"
                is_malicious = False
                reasons = ["Suspicious special character density"]
            else:
                score = 0.05 if suspicion_count > 0 else 0.0
                threat_level = "LOW"
                is_malicious = False
                reasons = ["Clean payload"]

        return ThreatAnalysisResult(
            score=score,
            threat_level=threat_level,
            threats_detected=threats,
            reasons=reasons,
            is_malicious=is_malicious,
        )


@dataclass
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float
    reasons: List[str]


class AnomalyDetectorAgent:
    """Agent learning baseline traffic patterns and flagging statistical anomalies."""

    def __init__(self, sensitivity: float = 2.0):
        self.sensitivity = sensitivity
        self.is_trained: bool = False
        self.baseline_stats: Dict[str, Any] = {}
        self.known_paths: Set[str] = set()
        self.known_methods: Set[str] = set()

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    async def learn_baseline(self, samples: List[RequestContext]):
        if not samples:
            return
        lengths = [len(s.get_full_payload()) for s in samples]
        entropies = [self._entropy(s.get_full_payload()) for s in samples]

        mean_len = sum(lengths) / len(lengths)
        variance_len = sum((x - mean_len) ** 2 for x in lengths) / max(1, len(lengths))
        std_len = math.sqrt(variance_len)

        mean_ent = sum(entropies) / len(entropies)
        variance_ent = sum((x - mean_ent) ** 2 for x in entropies) / max(1, len(entropies))
        std_ent = math.sqrt(variance_ent)

        self.baseline_stats = {
            "mean_length": mean_len,
            "std_length": max(std_len, 5.0),
            "mean_entropy": mean_ent,
            "std_entropy": max(std_ent, 0.5),
        }
        self.known_paths = {s.path for s in samples}
        self.known_methods = {s.method for s in samples}
        self.is_trained = True

    async def detect_anomaly(self, context: RequestContext) -> AnomalyResult:
        if not self.is_trained:
            return AnomalyResult(is_anomaly=False, anomaly_score=0.0, reasons=["Baseline not trained"])

        reasons = []
        scores = []
        payload = context.get_full_payload()
        p_len = len(payload)
        p_ent = self._entropy(payload)

        # Check payload length deviation
        mean_len = self.baseline_stats["mean_length"]
        std_len = self.baseline_stats["std_length"]
        z_len = abs(p_len - mean_len) / std_len
        if z_len > self.sensitivity:
            scores.append(min(1.0, 0.3 * z_len))
            reasons.append(f"Payload length deviation (z-score: {z_len:.2f})")

        # Check entropy deviation
        mean_ent = self.baseline_stats["mean_entropy"]
        std_ent = self.baseline_stats["std_entropy"]
        z_ent = abs(p_ent - mean_ent) / std_ent
        if z_ent > self.sensitivity:
            scores.append(min(1.0, 0.25 * z_ent))
            reasons.append(f"Entropy deviation (z-score: {z_ent:.2f})")

        # Check HTTP method
        if self.known_methods and context.method not in self.known_methods:
            scores.append(0.8)
            reasons.append(f"Unusual HTTP method: {context.method}")

        if not scores:
            return AnomalyResult(is_anomaly=False, anomaly_score=0.1, reasons=["Normal traffic profile"])

        max_score = round(min(1.0, max(scores)), 3)
        is_anomaly = max_score >= 0.6
        return AnomalyResult(is_anomaly=is_anomaly, anomaly_score=max_score, reasons=reasons)


@dataclass
class EvaluationResult:
    decision: Decision
    reason: str
    threat_score: float
    anomaly_score: float
    is_rate_limited: bool
    details: Dict[str, Any] = field(default_factory=dict)


class FirewallEngine:
    """Agentic Firewall Orchestration Engine coordinating multiple security agents."""

    def __init__(
        self,
        threat_intel_db: Optional[ThreatIntelDB] = None,
        rate_limiter: Optional[RateLimiterAgent] = None,
        threat_analyzer: Optional[ThreatAnalyzerAgent] = None,
        anomaly_detector: Optional[AnomalyDetectorAgent] = None,
        block_threshold: float = 0.8,
        challenge_threshold: float = 0.5,
    ):
        self.threat_intel_db = threat_intel_db or ThreatIntelDB()
        self.rate_limiter = rate_limiter or RateLimiterAgent()
        self.threat_analyzer = threat_analyzer or ThreatAnalyzerAgent(self.threat_intel_db)
        self.anomaly_detector = anomaly_detector or AnomalyDetectorAgent()
        self.block_threshold = block_threshold
        self.challenge_threshold = challenge_threshold

    async def evaluate(self, context: RequestContext) -> EvaluationResult:
        # 1. Rate Limiting Check
        is_limited = await self.rate_limiter.is_rate_limited(context.client_ip)
        if is_limited:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reason="Rate limit exceeded",
                threat_score=0.9,
                anomaly_score=0.0,
                is_rate_limited=True,
                details={"rate_limiter": "Rate limit threshold breached"},
            )

        # 2. Threat Analysis Check
        threat_res = await self.threat_analyzer.analyze(context)
        threat_score = threat_res.score

        # 3. Anomaly Detection Check
        anomaly_res = await self.anomaly_detector.detect_anomaly(context)
        anomaly_score = anomaly_res.anomaly_score

        details = {
            "threat_analysis": {
                "score": threat_score,
                "threat_level": threat_res.threat_level,
                "threats": threat_res.threats_detected,
                "reasons": threat_res.reasons,
            },
            "anomaly_detection": {
                "score": anomaly_score,
                "is_anomaly": anomaly_res.is_anomaly,
                "reasons": anomaly_res.reasons,
            },
        }

        # 4. Decision Policy
        if threat_score >= self.block_threshold or threat_res.threats_detected:
            return EvaluationResult(
                decision=Decision.BLOCK,
                reason=f"High threat detected: {', '.join(threat_res.threats_detected) or 'threat score threshold exceeded'}",
                threat_score=threat_score,
                anomaly_score=anomaly_score,
                is_rate_limited=False,
                details=details,
            )

        if threat_score >= self.challenge_threshold or (anomaly_res.is_anomaly and anomaly_score >= 0.6):
            reasons = []
            if threat_score >= self.challenge_threshold:
                reasons.append(f"Suspicious threat score ({threat_score})")
            if anomaly_res.is_anomaly:
                reasons.extend(anomaly_res.reasons)
            return EvaluationResult(
                decision=Decision.CHALLENGE,
                reason="; ".join(reasons) or "Behavioral challenge required",
                threat_score=threat_score,
                anomaly_score=anomaly_score,
                is_rate_limited=False,
                details=details,
            )

        return EvaluationResult(
            decision=Decision.ALLOW,
            reason="Request verified clean",
            threat_score=threat_score,
            anomaly_score=anomaly_score,
            is_rate_limited=False,
            details=details,
        )


class FirewallMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette ASGI Middleware intercepting requests with FirewallEngine."""

    def __init__(
        self,
        app,
        engine: FirewallEngine,
        block_status_code: int = 403,
        challenge_status_code: int = 403,
    ):
        super().__init__(app)
        self.engine = engine
        self.block_status_code = block_status_code
        self.challenge_status_code = challenge_status_code

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        query_params = dict(request.query_params)
        headers = dict(request.headers)

        body_bytes = await request.body()
        try:
            body_text = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""

        context = RequestContext(
            client_ip=client_ip,
            method=request.method,
            path=request.url.path,
            headers=headers,
            query_params=query_params,
            body=body_text,
        )

        evaluation = await self.engine.evaluate(context)

        if evaluation.decision == Decision.BLOCK:
            return JSONResponse(
                status_code=self.block_status_code,
                content={
                    "detail": "Request blocked by Agentic AI Firewall",
                    "reason": evaluation.reason,
                    "threat_score": evaluation.threat_score,
                },
                headers={"X-Firewall-Decision": Decision.BLOCK.value},
            )
        elif evaluation.decision == Decision.CHALLENGE:
            return JSONResponse(
                status_code=self.challenge_status_code,
                content={
                    "detail": "Challenge required by Agentic AI Firewall",
                    "reason": evaluation.reason,
                    "challenge": "CAPTCHA_REQUIRED",
                },
                headers={"X-Firewall-Decision": Decision.CHALLENGE.value},
            )

        response = await call_next(request)
        response.headers["X-Firewall-Decision"] = Decision.ALLOW.value
        return response


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def threat_intel_db() -> ThreatIntelDB:
    return ThreatIntelDB()


@pytest.fixture
def rate_limiter_agent() -> RateLimiterAgent:
    return RateLimiterAgent(threshold=3, window_seconds=1.0)


@pytest.fixture
def threat_analyzer_agent(threat_intel_db) -> ThreatAnalyzerAgent:
    return ThreatAnalyzerAgent(threat_intel_db=threat_intel_db, high_threshold=0.8, medium_threshold=0.5)


@pytest.fixture
def anomaly_detector_agent() -> AnomalyDetectorAgent:
    return AnomalyDetectorAgent(sensitivity=2.0)


@pytest.fixture
def baseline_training_contexts() -> List[RequestContext]:
    contexts = []
    normal_queries = ["q=laptop", "page=1&size=20", "category=books", "sort=desc", "filter=active"]
    normal_paths = ["/api/v1/search", "/api/v1/items", "/api/v1/profile"]
    for i in range(30):
        contexts.append(
            RequestContext(
                client_ip=f"192.168.1.{(i % 10) + 1}",
                method="GET" if i % 4 != 0 else "POST",
                path=normal_paths[i % len(normal_paths)],
                query_params={"query": normal_queries[i % len(normal_queries)]},
                headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
                body={"action": "view", "item_id": 100 + i} if i % 4 == 0 else "",
            )
        )
    return contexts


@pytest_asyncio.fixture
async def trained_anomaly_detector(anomaly_detector_agent, baseline_training_contexts) -> AnomalyDetectorAgent:
    await anomaly_detector_agent.learn_baseline(baseline_training_contexts)
    return anomaly_detector_agent


@pytest.fixture
def firewall_engine(
    threat_intel_db,
    rate_limiter_agent,
    threat_analyzer_agent,
    trained_anomaly_detector,
) -> FirewallEngine:
    return FirewallEngine(
        threat_intel_db=threat_intel_db,
        rate_limiter=rate_limiter_agent,
        threat_analyzer=threat_analyzer_agent,
        anomaly_detector=trained_anomaly_detector,
        block_threshold=0.8,
        challenge_threshold=0.5,
    )


@pytest.fixture
def clean_request_context() -> RequestContext:
    return RequestContext(
        client_ip="10.0.0.1",
        method="GET",
        path="/api/v1/search",
        query_params={"q": "wireless keyboard", "page": 1, "sort": "rating"},
        headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        body="",
    )


@pytest.fixture
def malicious_sqli_context() -> RequestContext:
    return RequestContext(
        client_ip="198.51.100.22",
        method="POST",
        path="/api/v1/login",
        query_params={},
        headers={"Content-Type": "application/json"},
        body={"username": "admin' OR '1'='1", "password": "password123"},
    )


@pytest.fixture
def malicious_xss_context() -> RequestContext:
    return RequestContext(
        client_ip="198.51.100.23",
        method="POST",
        path="/api/v1/comments",
        query_params={},
        headers={"Content-Type": "application/json"},
        body={"comment": "<script>alert('xss_attack')</script>"},
    )


@pytest.fixture
def malicious_traversal_context() -> RequestContext:
    return RequestContext(
        client_ip="198.51.100.24",
        method="GET",
        path="/api/v1/files",
        query_params={"filepath": "../../../../etc/passwd"},
        headers={},
        body="",
    )


@pytest.fixture
def malicious_cmdi_context() -> RequestContext:
    return RequestContext(
        client_ip="198.51.100.25",
        method="POST",
        path="/api/v1/tools/ping",
        query_params={},
        headers={"Content-Type": "application/json"},
        body={"target": "127.0.0.1; cat /etc/passwd"},
    )


@pytest.fixture
def sample_app(firewall_engine) -> FastAPI:
    app = FastAPI(title="Protected API")
    app.add_middleware(FirewallMiddleware, engine=firewall_engine)

    @app.get("/api/data")
    async def get_data(q: str = ""):
        return {"status": "ok", "query": q}

    @app.post("/api/submit")
    async def submit_data(request: Request):
        payload = await request.json()
        return {"status": "success", "data": payload}

    @app.get("/api/download")
    async def download_file(filepath: str = ""):
        return {"status": "success", "file": filepath}

    return app


@pytest.fixture
def test_client(sample_app) -> TestClient:
    return TestClient(sample_app, raise_server_exceptions=False)


# ============================================================================
# 1. TestThreatIntelDB
# ============================================================================

class TestThreatIntelDB:
    """Tests signature and pattern detection in ThreatIntelDB."""

    async def test_sql_injection_detection(self, threat_intel_db: ThreatIntelDB):
        sqli_samples = [
            "' OR '1'='1",
            "1; DROP TABLE users; --",
            "' UNION SELECT null, username, password FROM accounts--",
            "admin' --",
            "' OR 1=1 --",
            "SELECT * FROM credentials WHERE '1'='1'",
        ]
        for payload in sqli_samples:
            assert await threat_intel_db.is_sql_injection(payload) is True, f"Failed for {payload}"
            assert await threat_intel_db.detect_threat(payload) == "sql_injection"
            result = await threat_intel_db.check_threat(payload)
            assert result["is_threat"] is True
            assert "sql_injection" in result["threats"]

    async def test_xss_detection(self, threat_intel_db: ThreatIntelDB):
        xss_samples = [
            "<script>alert('xss')</script>",
            "<img src='x' onerror='alert(document.cookie)'/>",
            "<svg onload=alert(1)>",
            "javascript:alert('pwned')",
            "<iframe src='javascript:alert(1)'></iframe>",
        ]
        for payload in xss_samples:
            assert await threat_intel_db.is_xss(payload) is True, f"Failed for {payload}"
            assert await threat_intel_db.detect_threat(payload) == "xss"
            result = await threat_intel_db.check_threat(payload)
            assert result["is_threat"] is True
            assert "xss" in result["threats"]

    async def test_path_traversal_detection(self, threat_intel_db: ThreatIntelDB):
        traversal_samples = [
            "../../../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc/shadow",
            "folder/sub/../../../etc/passwd",
        ]
        for payload in traversal_samples:
            assert await threat_intel_db.is_path_traversal(payload) is True, f"Failed for {payload}"
            assert await threat_intel_db.detect_threat(payload) == "path_traversal"
            result = await threat_intel_db.check_threat(payload)
            assert result["is_threat"] is True
            assert "path_traversal" in result["threats"]

    async def test_command_injection_detection(self, threat_intel_db: ThreatIntelDB):
        cmdi_samples = [
            "; cat /etc/passwd",
            "| whoami",
            "&& ping -c 1 127.0.0.1",
            "$(id)",
            "`whoami`",
            "; rm -rf /",
        ]
        for payload in cmdi_samples:
            assert await threat_intel_db.is_command_injection(payload) is True, f"Failed for {payload}"
            assert await threat_intel_db.detect_threat(payload) == "command_injection"
            result = await threat_intel_db.check_threat(payload)
            assert result["is_threat"] is True
            assert "command_injection" in result["threats"]

    async def test_clean_requests(self, threat_intel_db: ThreatIntelDB):
        clean_samples = [
            "wireless mechanical gaming keyboard",
            "https://example.com/api/v1/items?category=shoes&size=10",
            "{\"user\": \"jane_doe\", \"email\": \"jane@example.com\"}",
            "sort=price_asc&limit=50&offset=100",
            "Valid description without any injection.",
        ]
        for payload in clean_samples:
            assert await threat_intel_db.is_sql_injection(payload) is False
            assert await threat_intel_db.is_xss(payload) is False
            assert await threat_intel_db.is_path_traversal(payload) is False
            assert await threat_intel_db.is_command_injection(payload) is False
            assert await threat_intel_db.detect_threat(payload) is None
            result = await threat_intel_db.check_threat(payload)
            assert result["is_threat"] is False
            assert len(result["threats"]) == 0

    async def test_multi_threat_payload(self, threat_intel_db: ThreatIntelDB):
        combined = "' OR 1=1; cat /etc/passwd <script>alert(1)</script>"
        result = await threat_intel_db.check_threat(combined)
        assert result["is_threat"] is True
        assert len(result["threats"]) >= 3
        assert "sql_injection" in result["threats"]
        assert "xss" in result["threats"]
        assert "command_injection" in result["threats"]


# ============================================================================
# 2. TestRateLimiterAgent
# ============================================================================

class TestRateLimiterAgent:
    """Tests rate limiter threshold enforcement and sliding window expiration."""

    async def test_rate_limiting_kicks_in_after_threshold(self, rate_limiter_agent: RateLimiterAgent):
        client = "192.168.1.100"
        # threshold is 3
        assert await rate_limiter_agent.is_rate_limited(client) is False
        assert await rate_limiter_agent.is_rate_limited(client) is False
        assert await rate_limiter_agent.is_rate_limited(client) is False

        # 4th request must kick in and be blocked
        is_limited = await rate_limiter_agent.is_rate_limited(client)
        assert is_limited is True, "Rate limit should kick in after 3 requests"

        # Subsequent request remains blocked
        assert await rate_limiter_agent.is_rate_limited(client) is True

    async def test_window_reset(self):
        fast_limiter = RateLimiterAgent(threshold=2, window_seconds=0.2)
        client = "10.0.0.99"

        assert await fast_limiter.is_rate_limited(client) is False
        assert await fast_limiter.is_rate_limited(client) is False
        # 3rd request blocked
        assert await fast_limiter.is_rate_limited(client) is True

        # Wait for the window to reset
        await asyncio.sleep(0.25)

        # After window reset, requests should be permitted again
        assert await fast_limiter.is_rate_limited(client) is False

    async def test_client_ip_isolation(self, rate_limiter_agent: RateLimiterAgent):
        client_a = "192.168.1.10"
        client_b = "192.168.1.20"

        # Exceed threshold for client A
        for _ in range(3):
            await rate_limiter_agent.is_rate_limited(client_a)
        assert await rate_limiter_agent.is_rate_limited(client_a) is True

        # Client B must remain unaffected
        assert await rate_limiter_agent.is_rate_limited(client_b) is False
        assert await rate_limiter_agent.get_remaining_capacity(client_b) == 2

    async def test_manual_reset(self, rate_limiter_agent: RateLimiterAgent):
        client = "172.16.0.5"
        for _ in range(3):
            await rate_limiter_agent.is_rate_limited(client)
        assert await rate_limiter_agent.is_rate_limited(client) is True

        await rate_limiter_agent.reset(client)
        assert await rate_limiter_agent.is_rate_limited(client) is False

    async def test_evaluate_context(self, rate_limiter_agent: RateLimiterAgent):
        ctx = RequestContext(client_ip="10.10.10.10")
        eval1 = await rate_limiter_agent.evaluate(ctx)
        assert eval1["limited"] is False
        assert eval1["remaining"] == 2


# ============================================================================
# 3. TestThreatAnalyzerAgent
# ============================================================================

class TestThreatAnalyzerAgent:
    """Tests threat scoring and classification by ThreatAnalyzerAgent."""

    async def test_malicious_sqli_gets_high_score(
        self, threat_analyzer_agent: ThreatAnalyzerAgent, malicious_sqli_context: RequestContext
    ):
        result = await threat_analyzer_agent.analyze(malicious_sqli_context)
        assert result.score >= 0.8, f"Expected high score >= 0.8, got {result.score}"
        assert result.threat_level in ["HIGH", "CRITICAL"]
        assert result.is_malicious is True
        assert "sql_injection" in result.threats_detected

    async def test_malicious_xss_gets_high_score(
        self, threat_analyzer_agent: ThreatAnalyzerAgent, malicious_xss_context: RequestContext
    ):
        result = await threat_analyzer_agent.analyze(malicious_xss_context)
        assert result.score >= 0.8
        assert result.is_malicious is True
        assert "xss" in result.threats_detected

    async def test_malicious_path_traversal_gets_high_score(
        self, threat_analyzer_agent: ThreatAnalyzerAgent, malicious_traversal_context: RequestContext
    ):
        result = await threat_analyzer_agent.analyze(malicious_traversal_context)
        assert result.score >= 0.8
        assert result.is_malicious is True
        assert "path_traversal" in result.threats_detected

    async def test_malicious_cmdi_gets_high_score(
        self, threat_analyzer_agent: ThreatAnalyzerAgent, malicious_cmdi_context: RequestContext
    ):
        result = await threat_analyzer_agent.analyze(malicious_cmdi_context)
        assert result.score >= 0.8
        assert result.is_malicious is True
        assert "command_injection" in result.threats_detected

    async def test_clean_request_gets_low_score(
        self, threat_analyzer_agent: ThreatAnalyzerAgent, clean_request_context: RequestContext
    ):
        result = await threat_analyzer_agent.analyze(clean_request_context)
        assert result.score < 0.2, f"Expected clean score < 0.2, got {result.score}"
        assert result.threat_level == "LOW"
        assert result.is_malicious is False
        assert len(result.threats_detected) == 0

    async def test_suspicious_payload_medium_score(self, threat_analyzer_agent: ThreatAnalyzerAgent):
        # A payload with high special character density but without matching specific exploit signatures
        suspicious_ctx = RequestContext(
            client_ip="192.168.1.5",
            body="filter=name;value='test';opt='--';tag=<custom>",
        )
        result = await threat_analyzer_agent.analyze(suspicious_ctx)
        assert 0.4 <= result.score <= 0.7
        assert result.threat_level == "MEDIUM"

    async def test_multi_vector_escalates_score(self, threat_analyzer_agent: ThreatAnalyzerAgent):
        multi_ctx = RequestContext(
            body="admin' OR 1=1; cat /etc/passwd; <script>alert(1)</script>"
        )
        result = await threat_analyzer_agent.analyze(multi_ctx)
        assert result.score >= 0.95
        assert result.threat_level == "CRITICAL"
        assert len(result.threats_detected) >= 2


# ============================================================================
# 4. TestAnomalyDetectorAgent
# ============================================================================

class TestAnomalyDetectorAgent:
    """Tests baseline learning and anomaly detection by AnomalyDetectorAgent."""

    async def test_baseline_learning(
        self, anomaly_detector_agent: AnomalyDetectorAgent, baseline_training_contexts: List[RequestContext]
    ):
        assert anomaly_detector_agent.is_trained is False
        await anomaly_detector_agent.learn_baseline(baseline_training_contexts)
        assert anomaly_detector_agent.is_trained is True
        assert "mean_length" in anomaly_detector_agent.baseline_stats
        assert "mean_entropy" in anomaly_detector_agent.baseline_stats
        assert anomaly_detector_agent.baseline_stats["mean_length"] > 0
        assert len(anomaly_detector_agent.known_methods) > 0

    async def test_normal_request_not_anomalous(
        self, trained_anomaly_detector: AnomalyDetectorAgent, clean_request_context: RequestContext
    ):
        result = await trained_anomaly_detector.detect_anomaly(clean_request_context)
        assert result.is_anomaly is False
        assert result.anomaly_score < 0.5
        assert "Normal traffic profile" in result.reasons

    async def test_payload_size_anomaly_detected(
        self, trained_anomaly_detector: AnomalyDetectorAgent
    ):
        huge_ctx = RequestContext(
            client_ip="10.0.0.2",
            method="POST",
            path="/api/v1/search",
            body="A" * 15000,  # Far exceeds typical 50-200 byte baseline
        )
        result = await trained_anomaly_detector.detect_anomaly(huge_ctx)
        assert result.is_anomaly is True
        assert result.anomaly_score >= 0.6
        assert any("length deviation" in r.lower() for r in result.reasons)

    async def test_entropy_anomaly_detected(
        self, trained_anomaly_detector: AnomalyDetectorAgent
    ):
        # Obfuscated high-entropy payload
        random_entropy_payload = "".join(chr(33 + (i * 37) % 90) for i in range(500))
        high_ent_ctx = RequestContext(
            client_ip="10.0.0.3",
            method="POST",
            path="/api/v1/search",
            body=random_entropy_payload,
        )
        result = await trained_anomaly_detector.detect_anomaly(high_ent_ctx)
        assert result.is_anomaly is True
        assert result.anomaly_score >= 0.6
        assert any("entropy deviation" in r.lower() for r in result.reasons)

    async def test_unseen_method_anomaly(
        self, trained_anomaly_detector: AnomalyDetectorAgent
    ):
        unusual_method_ctx = RequestContext(
            client_ip="10.0.0.4",
            method="DEBUG",  # Not in normal baseline GET/POST
            path="/api/v1/search",
            body="",
        )
        result = await trained_anomaly_detector.detect_anomaly(unusual_method_ctx)
        assert result.is_anomaly is True
        assert any("unusual http method" in r.lower() for r in result.reasons)

    async def test_untrained_detector_behavior(
        self, anomaly_detector_agent: AnomalyDetectorAgent, clean_request_context: RequestContext
    ):
        # When untrained, detector should safely return non-anomalous result
        result = await anomaly_detector_agent.detect_anomaly(clean_request_context)
        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0


# ============================================================================
# 5. TestFirewallEngine
# ============================================================================

class TestFirewallEngine:
    """Tests the full multi-agent pipeline and decisions (ALLOW, BLOCK, CHALLENGE)."""

    async def test_full_pipeline_allow_decision(
        self, firewall_engine: FirewallEngine, clean_request_context: RequestContext
    ):
        result = await firewall_engine.evaluate(clean_request_context)
        assert result.decision == Decision.ALLOW
        assert result.threat_score < 0.2
        assert result.is_rate_limited is False
        assert "clean" in result.reason.lower()

    async def test_full_pipeline_block_on_threat(
        self, firewall_engine: FirewallEngine, malicious_sqli_context: RequestContext
    ):
        result = await firewall_engine.evaluate(malicious_sqli_context)
        assert result.decision == Decision.BLOCK
        assert result.threat_score >= 0.8
        assert "sql_injection" in result.reason.lower()
        assert "threat_analysis" in result.details

    async def test_full_pipeline_block_on_rate_limit(
        self, firewall_engine: FirewallEngine
    ):
        ctx = RequestContext(client_ip="203.0.113.50", method="GET", path="/api/v1/status")
        # Trigger rate limiter threshold (threshold is 3)
        await firewall_engine.evaluate(ctx)
        await firewall_engine.evaluate(ctx)
        await firewall_engine.evaluate(ctx)

        # 4th evaluation must be blocked by rate limiter
        result = await firewall_engine.evaluate(ctx)
        assert result.decision == Decision.BLOCK
        assert result.is_rate_limited is True
        assert "rate limit" in result.reason.lower()

    async def test_full_pipeline_challenge_decision_on_anomaly(
        self, firewall_engine: FirewallEngine
    ):
        # A request that is structurally anomalous (e.g. extreme payload size)
        # but does NOT match explicit threat signatures
        anomalous_ctx = RequestContext(
            client_ip="198.51.100.99",
            method="POST",
            path="/api/v1/search",
            query_params={},
            body="benign_data=" + ("X" * 12000),
        )
        result = await firewall_engine.evaluate(anomalous_ctx)
        assert result.decision == Decision.CHALLENGE
        assert result.anomaly_score >= 0.6
        assert "challenge" in result.reason.lower()

    async def test_full_pipeline_challenge_decision_on_suspicious_payload(
        self, firewall_engine: FirewallEngine
    ):
        suspicious_ctx = RequestContext(
            client_ip="198.51.100.101",
            method="POST",
            path="/api/v1/search",
            body="filter=title;name='john';alias='--';opt=<any>",
        )
        result = await firewall_engine.evaluate(suspicious_ctx)
        assert result.decision == Decision.CHALLENGE
        assert result.threat_score >= 0.5
        assert result.threat_score < 0.8

    async def test_decision_result_structure_and_details(
        self, firewall_engine: FirewallEngine, clean_request_context: RequestContext
    ):
        result = await firewall_engine.evaluate(clean_request_context)
        assert isinstance(result, EvaluationResult)
        assert result.details is not None
        assert "threat_analysis" in result.details
        assert "anomaly_detection" in result.details


# ============================================================================
# 6. TestMiddleware
# ============================================================================

class TestMiddleware:
    """Tests FastAPI middleware integration with TestClient (200 on clean, 403 on block/challenge)."""

    def test_clean_get_request_allowed_200(self, test_client: TestClient):
        response = test_client.get("/api/data", params={"q": "mechanical keyboard"})
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["query"] == "mechanical keyboard"
        assert response.headers.get("X-Firewall-Decision") == Decision.ALLOW.value

    def test_clean_post_request_allowed_200(self, test_client: TestClient):
        response = test_client.post(
            "/api/submit",
            json={"title": "Antigravity Project", "description": "AI agent testing"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        assert response.headers.get("X-Firewall-Decision") == Decision.ALLOW.value

    def test_malicious_sqli_query_blocked_403(self, test_client: TestClient):
        response = test_client.get("/api/data", params={"q": "' OR '1'='1"})
        assert response.status_code == 403
        data = response.json()
        assert "blocked by agentic ai firewall" in data["detail"].lower()
        assert response.headers.get("X-Firewall-Decision") == Decision.BLOCK.value

    def test_malicious_xss_body_blocked_403(self, test_client: TestClient):
        response = test_client.post(
            "/api/submit",
            json={"comment": "<script>alert('xss_exploit')</script>"},
        )
        assert response.status_code == 403
        data = response.json()
        assert "blocked by agentic ai firewall" in data["detail"].lower()
        assert response.headers.get("X-Firewall-Decision") == Decision.BLOCK.value

    def test_path_traversal_blocked_403(self, test_client: TestClient):
        response = test_client.get("/api/download", params={"filepath": "../../../../etc/passwd"})
        assert response.status_code == 403
        assert response.headers.get("X-Firewall-Decision") == Decision.BLOCK.value

    def test_command_injection_blocked_403(self, test_client: TestClient):
        response = test_client.get("/api/data", params={"q": "; cat /etc/passwd"})
        assert response.status_code == 403
        assert response.headers.get("X-Firewall-Decision") == Decision.BLOCK.value

    def test_rate_limiting_enforcement_403(self, sample_app: FastAPI):
        # Create client with fresh engine instance
        client = TestClient(sample_app, raise_server_exceptions=False)
        headers = {"X-Forwarded-For": "185.220.101.5"}

        # 3 requests allowed
        r1 = client.get("/api/data", params={"q": "test1"}, headers=headers)
        assert r1.status_code == 200
        r2 = client.get("/api/data", params={"q": "test2"}, headers=headers)
        assert r2.status_code == 200
        r3 = client.get("/api/data", params={"q": "test3"}, headers=headers)
        assert r3.status_code == 200

        # 4th request rate-limited
        r4 = client.get("/api/data", params={"q": "test4"}, headers=headers)
        assert r4.status_code == 403
        assert "rate limit" in r4.json()["reason"].lower()
        assert r4.headers.get("X-Firewall-Decision") == Decision.BLOCK.value

    def test_challenge_response_handled_403(self, test_client: TestClient):
        # High entropy / size anomaly to trigger challenge
        payload = {"data": "X" * 15000}
        response = test_client.post("/api/submit", json=payload)
        assert response.status_code == 403
        data = response.json()
        assert "challenge required" in data["detail"].lower()
        assert response.headers.get("X-Firewall-Decision") == Decision.CHALLENGE.value
