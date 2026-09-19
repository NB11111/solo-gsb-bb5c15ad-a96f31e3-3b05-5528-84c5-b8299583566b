"""Pydantic request/response models for the normalization API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class EvaluateRequest(PolicyRequest):
    """Allow/deny lists (same rules as /normalize) plus addresses to evaluate."""

    addresses: list[str] = Field(
        default_factory=list,
        description=(
            "Bare IP addresses to evaluate (IPv4/IPv6 may be mixed); "
            "results are returned in this order."
        ),
        examples=[["10.1.0.1", "2001:db8::1"]],
    )

    @field_validator("addresses")
    @classmethod
    def _validate_address_list(cls, values: list[str]) -> list[str]:
        # Same 422 behaviour as the CIDR lists: ValueError -> HTTP 422.
        for value in values:
            parse_address(value)
        return values

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "allow": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"],
                    "deny": ["10.1.0.0/24", "10.0.0.0/8"],
                    "addresses": [
                        "10.1.0.1",
                        "10.1.1.1",
                        "10.2.0.1",
                        "2001:db8::1",
                        "192.0.2.1",
                    ],
                }
            ]
        }
    )


class Evaluation(BaseModel):
    decision: Literal["allow", "deny", "unmatched"] = Field(
        description="Outcome for the address.",
        examples=["deny"],
    )
    matched_cidr: str | None = Field(
        default=None,
        description="The winning CIDR entry; null when unmatched.",
        examples=["10.1.0.0/24"],
    )
    matched_side: Literal["allow", "deny"] | None = Field(
        default=None,
        description="Which list the winning entry came from; null when unmatched.",
        examples=["deny"],
    )


class EvaluateResponse(BaseModel):
    results: list[Evaluation] = Field(
        description="One evaluation per input address, in input order.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "results": [
                        {
                            "decision": "deny",
                            "matched_cidr": "10.1.0.0/24",
                            "matched_side": "deny",
                        },
                        {
                            "decision": "allow",
                            "matched_cidr": "10.1.0.0/16",
                            "matched_side": "allow",
                        },
                        {
                            "decision": "deny",
                            "matched_cidr": "10.0.0.0/8",
                            "matched_side": "deny",
                        },
                        {
                            "decision": "allow",
                            "matched_cidr": "2001:db8::/32",
                            "matched_side": "allow",
                        },
                        {
                            "decision": "unmatched",
                            "matched_cidr": None,
                            "matched_side": None,
                        },
                    ]
                }
            ]
        }
    )
