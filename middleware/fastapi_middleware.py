"""
middleware/fastapi_middleware.py

FastAPI Middleware for Agentic AI Firewall System.
Intercepts all incoming HTTP traffic, extracts comprehensive context telemetry,
calls FirewallEngine, and enforces security policies (BLOCK, CHALLENGE, ALLOW).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from typing import Any, Callable, Dict, Optional, Tuple, Union

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

# Configure module logger
logger = logging.getLogger("ai_firewall.middleware")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [AI-Firewall] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


async def extract_request_context(
    request: Request,
    max_body_size: int = 10 * 1024,
) -> Dict[str, Any]:
    """
    Extract comprehensive request context for firewall inspection:
    IP, headers, body (up to 10KB), query params, method, path,
    user-agent, referer, cookies, and request_id.
    """
    # 1. Extract Client IP (handling forwarders / reverse proxies)
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    elif request.headers.get("x-real-ip"):
        client_ip = request.headers["x-real-ip"].strip()
    elif request.client and request.client.host:
        client_ip = request.client.host
    else:
        client_ip = "127.0.0.1"

    # 2. Extract Body (up to max_body_size) and preserve stream for downstream handlers
    raw_body = await request.body()

    # Restore receive callable to allow downstream handlers to read the body
    body_sent = False

    async def receive() -> Dict[str, Any]:
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": raw_body, "more_body": False}
        return {"type": "http.request", "body": b"", "more_body": False}

    request._receive = receive

    truncated_body_bytes = raw_body[:max_body_size]
    try:
        body_str = truncated_body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_str = truncated_body_bytes.decode("utf-8", errors="replace")

    headers_dict = dict(request.headers)
    query_params_dict = dict(request.query_params)
    cookies_dict = dict(request.cookies)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    return {
        "ip": client_ip,
        "headers": headers_dict,
        "body": body_str,
        "raw_body": truncated_body_bytes,
        "query_params": query_params_dict,
        "method": request.method,
        "path": request.url.path,
        "user_agent": user_agent,
        "referer": referer,
        "cookies": cookies_dict,
        "request_id": request_id,
    }


def build_block_response(
    request_id: str,
    reason: str,
    score: float = 1.0,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Build a JSON 403 Forbidden response for blocked requests.
    Includes request_id and reason in JSON payload, and sets firewall headers.
    """
    content = {
        "error": "Forbidden",
        "action": "BLOCK",
        "request_id": request_id,
        "reason": reason,
        "score": score,
    }
    response_headers = {
        "X-Firewall-Action": "BLOCK",
        "X-Request-ID": request_id,
        "X-Firewall-Score": str(score),
    }
    if headers:
        response_headers.update(headers)

    return JSONResponse(
        status_code=403,
        content=content,
        headers=response_headers,
    )


def build_challenge_response(
    request_id: str,
    reason: str = "Challenge verification required",
    retry_after: int = 60,
    score: float = 0.5,
    headers: Optional[Dict[str, str]] = None,
) -> JSONResponse:
    """
    Build a JSON 429 Too Many Requests response for challenged requests.
    Includes retry-after header, request_id, reason, and firewall headers.
    """
    content = {
        "error": "Too Many Requests",
        "action": "CHALLENGE",
        "request_id": request_id,
        "reason": reason,
        "retry_after": retry_after,
        "score": score,
    }
    response_headers = {
        "Retry-After": str(retry_after),
        "X-Firewall-Action": "CHALLENGE",
        "X-Request-ID": request_id,
        "X-Firewall-Score": str(score),
    }
    if headers:
        response_headers.update(headers)

    return JSONResponse(
        status_code=429,
        content=content,
        headers=response_headers,
    )


class FirewallEngine:
    """
    Agentic AI Firewall Engine.
    Evaluates incoming request context against threat patterns, prompt injections,
    malicious payloads, and automated challenge policies.
    """

    def __init__(
        self,
        block_threshold: float = 0.8,
        challenge_threshold: float = 0.5,
    ) -> None:
        self.block_threshold = block_threshold
        self.challenge_threshold = challenge_threshold

    async def process_request(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate request context.
        Returns decision dict with keys: action, score, reason, request_id, [retry_after].
        """
        request_id = context.get("request_id") or str(uuid.uuid4())
        body = str(context.get("body") or "").lower()
        path = str(context.get("path") or "").lower()
        user_agent = str(context.get("user_agent") or "").lower()
        headers = context.get("headers") or {}

        # 1. Prompt Injection & Jailbreak Detection (Agentic AI specific)
        prompt_injections = [
            "ignore previous instructions",
            "disregard all prior instructions",
            "system prompt override",
            "jailbreak",
            "you are now an unrestricted ai",
            "dan mode",
            "developer mode enabled",
            "reveal system prompt",
            "leak secret prompt",
            "exfiltrate data",
        ]
        for pattern in prompt_injections:
            if pattern in body:
                return {
                    "action": "BLOCK",
                    "score": 0.99,
                    "reason": f"Prompt injection threat detected: '{pattern}'",
                    "request_id": request_id,
                }

        # 2. Web Attack Signatures (SQLi, XSS, Path Traversal, Command Injection)
        exploit_patterns = [
            ("../..", "Path traversal detected"),
            ("<script>", "Cross-site scripting (XSS) detected"),
            ("javascript:", "Cross-site scripting (XSS) detected"),
            ("union select", "SQL injection detected"),
            ("1=1--", "SQL injection detected"),
            ("/etc/passwd", "Sensitive file disclosure detected"),
            ("; rm -rf", "OS command injection detected"),
        ]
        for pattern, desc in exploit_patterns:
            if pattern in body or pattern in path:
                return {
                    "action": "BLOCK",
                    "score": 0.95,
                    "reason": f"Exploit pattern detected: {desc}",
                    "request_id": request_id,
                }

        # 3. Known Malicious Scanners
        malicious_tools = ["sqlmap", "nikto", "nmap", "masscan"]
        for tool in malicious_tools:
            if tool in user_agent:
                return {
                    "action": "BLOCK",
                    "score": 0.90,
                    "reason": f"Malicious scanning tool identified: {tool}",
                    "request_id": request_id,
                }

        # 4. Automated Bot / Challenge Check
        if "bot" in user_agent and not any(legit in user_agent for legit in ["googlebot", "bingbot"]):
            return {
                "action": "CHALLENGE",
                "score": 0.60,
                "reason": "Automated bot verification challenge required",
                "request_id": request_id,
                "retry_after": 30,
            }

        # Test Hooks
        if "test-block" in path or headers.get("x-test-action") == "BLOCK":
            return {
                "action": "BLOCK",
                "score": 1.0,
                "reason": "Explicit block test triggered",
                "request_id": request_id,
            }
        if "test-challenge" in path or headers.get("x-test-action") == "CHALLENGE":
            return {
                "action": "CHALLENGE",
                "score": 0.65,
                "reason": "Explicit challenge test triggered",
                "request_id": request_id,
                "retry_after": 60,
            }

        # Safe Request
        return {
            "action": "ALLOW",
            "score": 0.05,
            "reason": "Request verified and safe",
            "request_id": request_id,
        }


class AIFirewallMiddleware(BaseHTTPMiddleware):
    """
    FastAPI / Starlette middleware that intercepts incoming requests,
    extracts contextual telemetry, invokes the AI Firewall Engine,
    and enforces BLOCK, CHALLENGE, or ALLOW actions.
    """

    def __init__(
        self,
        app: ASGIApp,
        firewall_engine: Optional[Any] = None,
        max_body_size: int = 10 * 1024,
    ) -> None:
        super().__init__(app)
        self.firewall_engine = firewall_engine if firewall_engine is not None else FirewallEngine()
        self.max_body_size = max_body_size

    @staticmethod
    def _parse_decision(
        decision: Any,
        default_request_id: str,
    ) -> Tuple[str, str, float, str, int]:
        """
        Normalize decision object or dict into a standardized tuple:
        (action, reason, score, request_id, retry_after)
        """
        if isinstance(decision, dict):
            action = str(decision.get("action", "ALLOW")).strip().upper()
            reason = str(decision.get("reason", "Request processed by AI Firewall"))
            score = float(decision.get("score", 0.0))
            request_id = str(decision.get("request_id") or default_request_id)
            retry_after = int(decision.get("retry_after", 60))
        elif isinstance(decision, str):
            action = decision.strip().upper()
            reason = "Firewall rule applied"
            score = 1.0 if action == "BLOCK" else (0.5 if action == "CHALLENGE" else 0.0)
            request_id = default_request_id
            retry_after = 60
        else:
            action = str(getattr(decision, "action", "ALLOW")).strip().upper()
            reason = str(getattr(decision, "reason", "Request processed by AI Firewall"))
            score = float(getattr(decision, "score", 0.0))
            request_id = str(getattr(decision, "request_id", None) or default_request_id)
            retry_after = int(getattr(decision, "retry_after", 60))

        return action, reason, score, request_id, retry_after

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Intercept request, run firewall evaluation, and enforce response policies.
        """
        # 1. Extract context
        context = await extract_request_context(
            request, max_body_size=self.max_body_size
        )
        request_id = context["request_id"]

        # 2. Invoke FirewallEngine
        try:
            if inspect.iscoroutinefunction(self.firewall_engine.process_request):
                decision = await self.firewall_engine.process_request(context)
            else:
                decision = self.firewall_engine.process_request(context)
                if inspect.isawaitable(decision):
                    decision = await decision
        except Exception as exc:
            logger.error(
                f"FirewallEngine execution error for request {request_id}: {exc}",
                exc_info=True,
            )
            return build_block_response(
                request_id=request_id,
                reason=f"Firewall inspection failure: {str(exc)}",
                score=1.0,
            )

        # 3. Parse engine decision
        action, reason, score, decision_req_id, retry_after = self._parse_decision(
            decision, request_id
        )

        # 4. Handle BLOCK: return 403 JSON response
        if action == "BLOCK":
            logger.warning(
                f"FIREWALL BLOCK | ID: {decision_req_id} | Path: {request.url.path} | "
                f"IP: {context['ip']} | Reason: {reason} | Score: {score}"
            )
            return build_block_response(
                request_id=decision_req_id,
                reason=reason,
                score=score,
            )

        # 5. Handle CHALLENGE: return 429 JSON response with Retry-After header
        if action == "CHALLENGE":
            logger.info(
                f"FIREWALL CHALLENGE | ID: {decision_req_id} | Path: {request.url.path} | "
                f"IP: {context['ip']} | Retry-After: {retry_after}s | Reason: {reason}"
            )
            return build_challenge_response(
                request_id=decision_req_id,
                reason=reason,
                retry_after=retry_after,
                score=score,
            )

        # 6. Handle ALLOW: pass to route handler and measure response time
        start_time = time.perf_counter()
        response = await call_next(request)
        elapsed_time = time.perf_counter() - start_time

        # Inject mandatory firewall security headers
        response.headers["X-Firewall-Action"] = "ALLOW"
        response.headers["X-Request-ID"] = decision_req_id
        response.headers["X-Firewall-Score"] = str(score)
        response.headers["X-Process-Time"] = f"{elapsed_time:.6f}"

        logger.debug(
            f"FIREWALL ALLOW | ID: {decision_req_id} | Path: {request.url.path} | "
            f"Latency: {elapsed_time * 1000:.2f}ms"
        )
        return response


def create_app(
    firewall_engine: Optional[Any] = None,
    max_body_size: int = 10 * 1024,
) -> FastAPI:
    """
    Factory function to configure and return a FastAPI application
    instrumented with the AIFirewallMiddleware and demonstration routes.
    """
    app = FastAPI(
        title="Agentic AI Firewall Protected API",
        description="FastAPI service with real-time AI Firewall inspection and enforcement.",
        version="1.0.0",
    )

    # Register AIFirewallMiddleware
    app.add_middleware(
        AIFirewallMiddleware,
        firewall_engine=firewall_engine,
        max_body_size=max_body_size,
    )

    # Demo / Test Routes
    @app.get("/", tags=["Health"])
    async def root():
        return {
            "service": "Agentic AI Firewall Protected API",
            "status": "online",
            "message": "All requests are inspected by AI Firewall.",
        }

    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "healthy"}

    @app.post("/api/v1/chat", tags=["AI Operations"])
    async def chat_endpoint(request: Request):
        payload = await request.json()
        return {
            "status": "success",
            "message": "Prompt successfully verified and processed.",
            "data": payload,
        }

    @app.post("/api/v1/agent/action", tags=["AI Operations"])
    async def agent_action_endpoint(request: Request):
        payload = await request.json()
        return {
            "status": "success",
            "action_executed": True,
            "data": payload,
        }

    @app.get("/api/v1/resource", tags=["Protected Resources"])
    async def get_resource():
        return {
            "resource_id": "res_987654",
            "content": "Confidential data accessible only after firewall clearance.",
        }

    @app.get("/test-block", tags=["Testing"])
    async def trigger_block_demo():
        return {"message": "If you see this, block was not enforced."}

    @app.get("/test-challenge", tags=["Testing"])
    async def trigger_challenge_demo():
        return {"message": "If you see this, challenge was not enforced."}

    return app


# Default application instance for ASGI servers (e.g. uvicorn middleware.fastapi_middleware:app)
app = create_app()
