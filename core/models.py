"""ORM models.

Hierarchy:
  Target   — an AI system under test (an LLM endpoint / chatbot / agent)
  Campaign — a named assessment against one target (a set of probes)
  Run      — one execution of a campaign
  Attempt  — one orchestrated attack attempt within a run (may be multi-turn)
  Step     — a single request/response exchange ("attach step") of an attempt
  Finding  — a confirmed weakness distilled from a successful attempt
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (JSON, Boolean, Column, DateTime, Float, ForeignKey,
                        Integer, String, Text)
from sqlalchemy.orm import relationship

from .db import Base


def _now():
    return datetime.utcnow()


class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    kind = Column(String(40), default="http_chat")  # http_chat | demo_agent
    endpoint = Column(String(600), default="")
    # request shaping for generic http_chat targets
    http_method = Column(String(10), default="POST")
    headers = Column(JSON, default=dict)
    body_template = Column(Text, default='{"message": "{{PROMPT}}"}')
    response_path = Column(String(200), default="reply")  # dotted path to text
    # safety gate
    authorized = Column(Boolean, default=False)
    authorization_note = Column(Text, default="")
    # host engagements only: permit link-local/loopback targets (bundled lab).
    allow_internal = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)

    campaigns = relationship("Campaign", back_populates="target", cascade="all, delete-orphan")


class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"))
    probes = Column(JSON, default=list)       # list of probe ids
    orchestrator = Column(String(40), default="single_turn")
    max_turns = Column(Integer, default=6)
    # Authenticated testing: session cookies for this campaign (one per line, or
    # "name=value; name2=value2"). Injected as a Cookie header into web probes
    # and the cookie-capable tool-runner tools so scans run logged-in.
    session_cookies = Column(Text, default="")
    created_at = Column(DateTime, default=_now)

    target = relationship("Target", back_populates="campaigns")
    runs = relationship("Run", back_populates="campaign", cascade="all, delete-orphan")


class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id", ondelete="CASCADE"))
    status = Column(String(20), default="queued")  # queued|running|done|error|stopped
    started_at = Column(DateTime, default=_now)
    finished_at = Column(DateTime, nullable=True)
    summary = Column(JSON, default=dict)
    error = Column(Text, default="")

    campaign = relationship("Campaign", back_populates="runs")
    attempts = relationship("Attempt", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")


class Attempt(Base):
    __tablename__ = "attempts"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"))
    probe = Column(String(80))
    technique = Column(String(120))
    phase = Column(String(30), default="")   # kill-chain phase (pentest engagements)
    owasp = Column(String(20), default="")
    atlas = Column(String(40), default="")
    severity = Column(String(20), default="info")
    success = Column(Boolean, default=False)
    score = Column(Float, default=0.0)
    objective = Column(Text, default="")
    rationale = Column(Text, default="")     # why the judge scored it this way
    evidence = Column(Text, default="")      # extracted proof (leaked secret, shell output...)
    created_at = Column(DateTime, default=_now)

    run = relationship("Run", back_populates="attempts")
    steps = relationship("Step", back_populates="attempt", cascade="all, delete-orphan",
                         order_by="Step.idx")


class Step(Base):
    __tablename__ = "steps"
    id = Column(Integer, primary_key=True)
    attempt_id = Column(Integer, ForeignKey("attempts.id", ondelete="CASCADE"))
    idx = Column(Integer, default=0)
    role = Column(String(20), default="attacker")  # attacker request -> target response
    prompt = Column(Text, default="")
    response = Column(Text, default="")
    note = Column(Text, default="")          # human-readable "what this step does"
    latency_ms = Column(Integer, default=0)
    created_at = Column(DateTime, default=_now)

    attempt = relationship("Attempt", back_populates="steps")


class Setting(Base):
    """Key/value store for runtime configuration the operator can change from
    the console (e.g. the attacker/judge LLM). Overrides the env defaults in
    config.py when present. Single-tenant, self-hosted tool — one row per key."""
    __tablename__ = "settings"
    key = Column(String(80), primary_key=True)
    value = Column(JSON, default=dict)
    updated_at = Column(DateTime, default=_now, onupdate=_now)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"))
    attempt_id = Column(Integer, ForeignKey("attempts.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(300))
    severity = Column(String(20), default="info")
    owasp = Column(String(20), default="")
    atlas = Column(String(40), default="")
    description = Column(Text, default="")
    evidence = Column(Text, default="")
    remediation = Column(Text, default="")
    created_at = Column(DateTime, default=_now)

    run = relationship("Run", back_populates="findings")
