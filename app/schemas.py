"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from app.policy import parse_address, parse_network


class PolicyRequest(BaseModel):
    allow: list[str] = Field(
        default_factory=list,
        description="Allowed CIDR list (IPv4/IPv6 may be mixed).",
    )
    deny: list[str] = Field(
        default_factory=list,
        description="Denied CIDR list (IPv4/IPv6 may be mixed).",
    )

    @field_validator("allow", "deny")
    @classmethod
    def _validate_cidr_list(cls, values: list[str]) -> list[str]:
        # A ValueError raised here is turned by FastAPI into an HTTP 422
        # response carrying the offending field and value.
        for value in values:
            parse_network(value)
        return values


class EvaluateRequest(PolicyRequest):
    addresses: list[str] = Field(
        default_factory=list,
        description="Bare IPv4/IPv6 addresses to evaluate, in response order.",
    )

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        for value in values:
            parse_address(value)
        return values


class ListStats(BaseModel):
    input: int = Field(description="Raw number of entries in the request list.")
    unique: int = Field(description="Distinct networks after de-duplication.")
    duplicates_removed: int = Field(description="input - unique.")
    ipv4: int = Field(description="Distinct IPv4 networks after de-duplication.")
    ipv6: int = Field(description="Distinct IPv6 networks after de-duplication.")


class OutputStats(BaseModel):
    ipv4: int
    ipv6: int
    total: int


class Stats(BaseModel):
    allow: ListStats
    deny: ListStats
    output: OutputStats


class NormalizeResponse(BaseModel):
    ipv4: list[str] = Field(
        description="allow - deny for IPv4, minimal, non-overlapping, sorted.",
    )
    ipv6: list[str] = Field(
        description="allow - deny for IPv6, minimal, non-overlapping, sorted.",
    )
    stats: Stats


class AddressDecision(BaseModel):
    decision: Literal["allow", "deny", "unmatched"] = Field(
        description=(
            "Winner side after longest-prefix matching; 'unmatched' when no "
            "list entry contains the address."
        ),
    )
    matched_cidr: str | None = Field(
        description="Canonical CIDR of the winning entry; null when unmatched.",
    )
    matched_side: Literal["allow", "deny"] | None = Field(
        description="List the winning entry came from; null when unmatched.",
    )
