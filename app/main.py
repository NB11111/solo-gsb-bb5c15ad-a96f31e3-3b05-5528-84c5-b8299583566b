"""FastAPI application exposing POST /normalize and POST /evaluate."""

from __future__ import annotations

from fastapi import FastAPI

from app.policy import evaluate, normalize
from app.schemas import (
    EvaluateRequest,
    EvaluateResponse,
    NormalizeResponse,
    PolicyRequest,
)

app = FastAPI(
    title="CIDR Policy Normalizer",
    description=(
        "Compute allow-minus-deny for IPv4/IPv6 CIDR lists, returning the "
        "equivalent, non-overlapping, minimum-count CIDR set, and evaluate "
        "individual addresses against the lists by longest-prefix match."
    ),
    version="1.0.0",
)


@app.get("/health", tags=["ops"])
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/normalize",
    response_model=NormalizeResponse,
    tags=["policy"],
    summary="Normalize allow/deny CIDR lists into allow minus deny",
)
def normalize_policy(request: PolicyRequest) -> dict:
    return normalize(request.allow, request.deny)


@app.post(
    "/evaluate",
    response_model=EvaluateResponse,
    tags=["policy"],
    summary="Longest-prefix-match addresses against allow/deny lists",
)
def evaluate_addresses(request: EvaluateRequest) -> dict:
    return evaluate(request.allow, request.deny, request.addresses)
