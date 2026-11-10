"""Firewall Engine Module for Agentic AI Firewall System.

This module provides the core orchestration engine that runs multiple inspection
and security agents concurrently, aggregates their individual decisions using
configurable weights, maps risk scores to operational actions (ALLOW, BLOCK,
CHALLENGE) via configurable threat thresholds, provides structured JSON logging,
and tracks comprehensive runtime metrics.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import inspect
import json
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Union
import uuid


class Action(str, Enum):
    """Supported firewall decision actions."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"


DEFAULT_AGENT_WEIGHTS: Dict[str, float] = {
    "prompt_injection": 1.0,
    "jailbreak": 1.0,
    "pii_detector": 0.8,
    "toxicity": 0.7,
    "tool_abuse": 0.9,
    "system_tampering": 1.0,
}


@dataclass
class AgentResult:
    """Individual inspection agent output."""
    agent_name: str
    score: float
    action: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0


@dataclass
class FirewallDecision:
    """Final aggregated decision produced by the FirewallEngine."""
    action: str  # ALLOW, BLOCK, or CHALLENGE
    score: float
    reasons: List[str] = field(default_factory=list)
    agent_scores: Dict[str, float] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to a serializable dictionary."""
        return asdict(self)

    @property
    def is_allowed(self) -> bool:
        """Check if action is ALLOW."""
        return self.action == Action.ALLOW.value

    @property
    def is_blocked(self) -> bool:
        """Check if action is BLOCK."""
        return self.action == Action.BLOCK.value

    @property
    def is_challenged(self) -> bool:
        """Check if action is CHALLENGE."""
        return self.action == Action.CHALLENGE.value


class FirewallEngine:
    """Main orchestrator that runs all firewall agents concurrently and aggregates their decisions."""

    def __init__(
        self,
        agents: Optional[Union[List[Any], Dict[str, Any]]] = None,
        weights: Optional[Dict[str, float]] = None,
        allow_threshold: float = 0.3,
        challenge_threshold: float = 0.6,
        block_threshold: float = 0.8,
        logger: Optional[logging.Logger] = None,
        fail_closed: bool = False,
    ) -> None:
        """Initialize the FirewallEngine.

        Args:
            agents: Optional list or dict of agent instances/callables.
            weights: Optional dictionary mapping agent names to relative weights.
            allow_threshold: Threat scores <= this value are ALLOWed (default: 0.3).
            challenge_threshold: Threat scores >= this value and < block_threshold
                trigger a CHALLENGE (default: 0.6).
            block_threshold: Threat scores >= this value are BLOCKed (default: 0.8).
            logger: Custom logger instance. If omitted, a standard logger is used.
            fail_closed: If True, agent execution failures contribute maximum threat (1.0);
                otherwise failure is logged and safe default (0.0) is assigned.
        """
        self.allow_threshold: float = float(allow_threshold)
        self.challenge_threshold: float = float(challenge_threshold)
        self.block_threshold: float = float(block_threshold)
        self.fail_closed: bool = fail_closed
        self.logger: logging.Logger = logger or logging.getLogger("firewall.engine")

        # Configure agent weights
        self.weights: Dict[str, float] = (
            dict(weights) if weights is not None else dict(DEFAULT_AGENT_WEIGHTS)
        )

        # Register agents internally as Dict[str, Any]
        self.agents: Dict[str, Any] = {}
        if agents:
            if isinstance(agents, dict):
                for name, agent in agents.items():
                    self.add_agent(agent, name=name)
            elif isinstance(agents, (list, tuple, set)):
                for idx, agent in enumerate(agents):
                    self.add_agent(agent, name=None, default_index=idx)

        # Runtime performance metrics
        self._total_requests: int = 0
        self._action_counts: Dict[str, int] = {
            Action.ALLOW.value: 0,
            Action.CHALLENGE.value: 0,
            Action.BLOCK.value: 0,
        }
        self._total_score: float = 0.0
        self._total_latency_ms: float = 0.0
        self._min_latency_ms: float = float("inf")
        self._max_latency_ms: float = 0.0
        self._start_time: float = time.time()
        self._lock: asyncio.Lock = asyncio.Lock()

    def add_agent(
        self,
        agent: Any,
        name: Optional[str] = None,
        weight: Optional[float] = None,
        default_index: int = 0,
    ) -> None:
        """Register an agent with an optional name and weight."""
        agent_name = (
            name
            or getattr(agent, "name", None)
            or getattr(agent, "__name__", None)
            or f"{agent.__class__.__name__}_{default_index}"
        )
        self.agents[agent_name] = agent
        if weight is not None:
            self.weights[agent_name] = float(weight)
        elif agent_name not in self.weights:
            self.weights[agent_name] = 1.0

    def remove_agent(self, name: str) -> Optional[Any]:
        """Remove a registered agent by name."""
        return self.agents.pop(name, None)

    def set_weight(self, agent_name: str, weight: float) -> None:
        """Update or set the weight for a specific agent."""
        self.weights[agent_name] = float(weight)

    async def _invoke_agent(self, name: str, agent: Any, context: dict) -> Dict[str, Any]:
        """Safely invokes a single agent supporting sync/async methods and callables."""
        agent_start = time.perf_counter()
        try:
            if hasattr(agent, "process_request") and callable(agent.process_request):
                res = agent.process_request(context)
            elif hasattr(agent, "analyze") and callable(agent.analyze):
                res = agent.analyze(context)
            elif hasattr(agent, "process") and callable(agent.process):
                res = agent.process(context)
            elif hasattr(agent, "evaluate") and callable(agent.evaluate):
                res = agent.evaluate(context)
            elif callable(agent):
                res = agent(context)
            else:
                raise TypeError(f"Agent '{name}' has no supported evaluation method or callable interface")

            if inspect.isawaitable(res):
                res = await res

            latency = (time.perf_counter() - agent_start) * 1000.0
            return self._normalize_agent_result(name, res, latency)

        except Exception as exc:
            latency = (time.perf_counter() - agent_start) * 1000.0
            self.logger.error("Agent '%s' failed during execution: %s", name, exc, exc_info=True)
            fallback_score = 1.0 if self.fail_closed else 0.0
            fallback_action = Action.BLOCK.value if self.fail_closed else Action.ALLOW.value
            return {
                "agent_name": name,
                "score": fallback_score,
                "action": fallback_action,
                "reasons": [f"Agent '{name}' execution error: {str(exc)}"],
                "latency_ms": latency,
                "error": str(exc),
            }

    def _normalize_agent_result(self, default_name: str, result: Any, latency_ms: float = 0.0) -> Dict[str, Any]:
        """Normalizes heterogeneous agent responses into a standard dictionary representation."""
        if isinstance(result, AgentResult):
            return {
                "agent_name": result.agent_name or default_name,
                "score": max(0.0, min(1.0, float(result.score))),
                "action": result.action,
                "reasons": list(result.reasons),
                "latency_ms": latency_ms or result.latency_ms,
            }
        elif isinstance(result, dict):
            name = result.get("agent_name") or result.get("name") or default_name
            raw_score = result.get("score")
            action = result.get("action")
            raw_reasons = result.get("reasons") or result.get("reason") or []
            if isinstance(raw_reasons, str):
                reasons = [raw_reasons]
            else:
                reasons = [str(r) for r in raw_reasons if r]

            if raw_score is None:
                if action == Action.BLOCK.value:
                    score = 1.0
                elif action == Action.CHALLENGE.value:
                    score = self.challenge_threshold
                else:
                    score = 0.0
            else:
                score = max(0.0, min(1.0, float(raw_score)))

            return {
                "agent_name": str(name),
                "score": score,
                "action": action,
                "reasons": reasons,
                "latency_ms": latency_ms,
            }
        elif hasattr(result, "score"):
            name = getattr(result, "agent_name", None) or getattr(result, "name", None) or default_name
            score = max(0.0, min(1.0, float(getattr(result, "score", 0.0))))
            raw_reasons = getattr(result, "reasons", None) or getattr(result, "reason", None) or []
            if isinstance(raw_reasons, str):
                reasons = [raw_reasons]
            else:
                reasons = [str(r) for r in raw_reasons if r]
            action = getattr(result, "action", None)
            return {
                "agent_name": str(name),
                "score": score,
                "action": action,
                "reasons": reasons,
                "latency_ms": latency_ms,
            }
        elif isinstance(result, (int, float)):
            return {
                "agent_name": default_name,
                "score": max(0.0, min(1.0, float(result))),
                "action": None,
                "reasons": [],
                "latency_ms": latency_ms,
            }
        elif isinstance(result, (list, tuple)) and len(result) >= 2:
            name = str(result[0])
            score = max(0.0, min(1.0, float(result[1])))
            reasons = [str(r) for r in result[2]] if len(result) > 2 and isinstance(result[2], (list, tuple)) else []
            return {
                "agent_name": name,
                "score": score,
                "action": None,
                "reasons": reasons,
                "latency_ms": latency_ms,
            }
        else:
            return {
                "agent_name": default_name,
                "score": 0.0,
                "action": None,
                "reasons": [],
                "latency_ms": latency_ms,
            }

    async def _aggregate_decisions(
        self, agent_results: list, request_id: Optional[str] = None
    ) -> FirewallDecision:
        """Weighs each agent's output by configurable weights and produces a final

        ALLOW/BLOCK/CHALLENGE decision.
        """
        agent_scores: Dict[str, float] = {}
        all_reasons: List[str] = []
        explicit_actions: List[str] = []
        resolved_req_id = request_id

        weighted_score_sum = 0.0
        total_weight = 0.0

        for idx, item in enumerate(agent_results):
            if isinstance(item, Exception):
                self.logger.error("Exception received in aggregation: %s", item)
                name = f"failed_agent_{idx}"
                score = 1.0 if self.fail_closed else 0.0
                all_reasons.append(f"Agent failed with exception: {item}")
                agent_scores[name] = score
                weight = self.weights.get(name, 1.0)
                weighted_score_sum += score * weight
                total_weight += weight
                continue

            normalized = self._normalize_agent_result(f"agent_{idx}", item)
            name = normalized["agent_name"]
            score = normalized["score"]
            reasons = normalized["reasons"]
            action = normalized.get("action")

            agent_scores[name] = score
            all_reasons.extend(reasons)
            if action:
                explicit_actions.append(action)

            weight = self.weights.get(name, 1.0)
            weighted_score_sum += score * weight
            total_weight += weight

            if not resolved_req_id and isinstance(item, dict) and "request_id" in item:
                resolved_req_id = item["request_id"]

        if not resolved_req_id:
            resolved_req_id = str(uuid.uuid4())

        # Calculate final normalized weighted threat score
        if total_weight > 0.0:
            final_score = round(weighted_score_sum / total_weight, 4)
        else:
            final_score = 0.0

        final_score = max(0.0, min(1.0, final_score))

        # Decision threshold evaluation
        if final_score >= self.block_threshold:
            final_action = Action.BLOCK.value
        elif final_score >= self.challenge_threshold:
            final_action = Action.CHALLENGE.value
        elif final_score <= self.allow_threshold:
            final_action = Action.ALLOW.value
        else:
            # Ambiguous risk zone (allow_threshold < final_score < challenge_threshold):
            # Escalate to CHALLENGE if any agent recommended CHALLENGE/BLOCK or flagged threat reasons
            if any(act in (Action.BLOCK.value, Action.CHALLENGE.value) for act in explicit_actions):
                final_action = Action.CHALLENGE.value
            elif all_reasons:
                final_action = Action.CHALLENGE.value
            else:
                final_action = Action.CHALLENGE.value

        # Deduplicate reasons while preserving order
        deduped_reasons: List[str] = []
        seen = set()
        for r in all_reasons:
            if r not in seen:
                seen.add(r)
                deduped_reasons.append(r)

        return FirewallDecision(
            action=final_action,
            score=final_score,
            reasons=deduped_reasons,
            agent_scores=agent_scores,
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=resolved_req_id,
        )

    async def _log_decision(self, request_context: dict, decision: FirewallDecision) -> None:
        """Emits structured JSON logging for every firewall decision."""
        log_entry = {
            "timestamp": decision.timestamp,
            "event": "firewall_decision",
            "request_id": decision.request_id,
            "action": decision.action,
            "score": decision.score,
            "reasons": decision.reasons,
            "agent_scores": decision.agent_scores,
            "request_context": request_context,
        }
        try:
            log_str = json.dumps(log_entry, default=str)
        except Exception as exc:
            self.logger.warning("Failed to serialize full request context: %s", exc)
            log_entry["request_context"] = str(request_context)
            log_str = json.dumps(log_entry, default=str)

        self.logger.info(log_str)

    async def process_request(self, request_context: dict) -> FirewallDecision:
        """Processes an incoming request by executing all configured agents concurrently

        using asyncio.gather, aggregates their decisions, logs the outcome, and updates
        engine metrics.
        """
        start_time = time.perf_counter()
        req_context = dict(request_context) if request_context else {}
        request_id = req_context.get("request_id") or str(uuid.uuid4())
        req_context["request_id"] = request_id

        if not self.agents:
            decision = FirewallDecision(
                action=Action.ALLOW.value,
                score=0.0,
                reasons=["No inspection agents configured; request allowed by default."],
                agent_scores={},
                timestamp=datetime.now(timezone.utc).isoformat(),
                request_id=request_id,
            )
        else:
            # Run all agents concurrently with asyncio.gather
            tasks = [
                self._invoke_agent(name, agent, req_context)
                for name, agent in self.agents.items()
            ]
            agent_results = await asyncio.gather(*tasks, return_exceptions=True)
            decision = await self._aggregate_decisions(list(agent_results), request_id=request_id)

        # Structured JSON logging
        await self._log_decision(req_context, decision)

        # Record runtime metrics
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        async with self._lock:
            self._record_metrics(decision, latency_ms)

        return decision

    def _record_metrics(self, decision: FirewallDecision, latency_ms: float) -> None:
        """Updates internal telemetry counters and metrics."""
        self._total_requests += 1
        if decision.action in self._action_counts:
            self._action_counts[decision.action] += 1
        else:
            self._action_counts[decision.action] = 1

        self._total_score += decision.score
        self._total_latency_ms += latency_ms

        if latency_ms < self._min_latency_ms:
            self._min_latency_ms = latency_ms
        if latency_ms > self._max_latency_ms:
            self._max_latency_ms = latency_ms

    async def get_stats(self) -> dict:
        """Returns runtime performance and operational statistics."""
        async with self._lock:
            total = self._total_requests
            avg_score = round(self._total_score / total, 4) if total > 0 else 0.0
            avg_latency = round(self._total_latency_ms / total, 2) if total > 0 else 0.0
            min_latency = round(self._min_latency_ms, 2) if self._min_latency_ms != float("inf") else 0.0
            max_latency = round(self._max_latency_ms, 2)

            return {
                "total_requests": total,
                "allowed_requests": self._action_counts.get(Action.ALLOW.value, 0),
                "challenged_requests": self._action_counts.get(Action.CHALLENGE.value, 0),
                "blocked_requests": self._action_counts.get(Action.BLOCK.value, 0),
                "action_counts": dict(self._action_counts),
                "allow_rate": round(self._action_counts.get(Action.ALLOW.value, 0) / total, 4) if total > 0 else 0.0,
                "challenge_rate": round(self._action_counts.get(Action.CHALLENGE.value, 0) / total, 4) if total > 0 else 0.0,
                "block_rate": round(self._action_counts.get(Action.BLOCK.value, 0) / total, 4) if total > 0 else 0.0,
                "avg_score": avg_score,
                "avg_latency_ms": avg_latency,
                "min_latency_ms": min_latency,
                "max_latency_ms": max_latency,
                "uptime_seconds": round(time.time() - self._start_time, 2),
                "thresholds": {
                    "allow_threshold": self.allow_threshold,
                    "challenge_threshold": self.challenge_threshold,
                    "block_threshold": self.block_threshold,
                },
                "agent_weights": dict(self.weights),
                "active_agents": list(self.agents.keys()),
            }
