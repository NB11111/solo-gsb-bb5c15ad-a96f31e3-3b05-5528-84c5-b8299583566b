"""API-level tests for POST /normalize and POST /evaluate."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_normalize_basic():
    response = client.post(
        "/normalize",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
            "deny": ["10.0.0.128/25"],
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ipv4"] == ["10.0.0.0/25"]
    assert data["ipv6"] == ["2001:db8::/32"]
    assert data["stats"]["allow"] == {
        "input": 3, "unique": 2, "duplicates_removed": 1,
        "ipv4": 1, "ipv6": 1,
    }
    assert data["stats"]["deny"] == {
        "input": 1, "unique": 1, "duplicates_removed": 0,
        "ipv4": 1, "ipv6": 0,
    }
    assert data["stats"]["output"] == {"ipv4": 1, "ipv6": 1, "total": 2}


def test_empty_body_defaults_to_empty_lists():
    response = client.post("/normalize", json={})
    assert response.status_code == 200
    assert response.json() == {
        "ipv4": [],
        "ipv6": [],
        "stats": {
            "allow": {"input": 0, "unique": 0, "duplicates_removed": 0,
                      "ipv4": 0, "ipv6": 0},
            "deny": {"input": 0, "unique": 0, "duplicates_removed": 0,
                     "ipv4": 0, "ipv6": 0},
            "output": {"ipv4": 0, "ipv6": 0, "total": 0},
        },
    }


def test_invalid_cidr_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": ["10.0.0.0/24", "bogus"], "deny": []},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "allow" for err in detail)


def test_host_bits_return_422():
    response = client.post(
        "/normalize",
        json={"allow": [], "deny": ["10.0.0.1/24"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "deny" for err in response.json()["detail"])


def test_wrong_type_returns_422():
    response = client.post(
        "/normalize",
        json={"allow": [10], "deny": []},
    )
    assert response.status_code == 422


def test_doc_and_openapi_available():
    assert client.get("/docs").status_code == 200
    spec = client.get("/openapi.json").json()
    assert "/normalize" in spec["paths"]
    assert "/evaluate" in spec["paths"]


def test_evaluate_basic():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32"],
            "deny": ["10.1.0.0/24", "10.0.0.0/8"],
            "addresses": [
                "10.1.0.1",
                "10.1.1.1",
                "10.2.0.1",
                "2001:db8::1",
                "192.0.2.1",
            ],
        },
    )
    assert response.status_code == 200
    assert response.json() == {
        "results": [
            # Longest prefix wins: deny /24 beats allow /16 and /8.
            {"decision": "deny", "matched_cidr": "10.1.0.0/24",
             "matched_side": "deny"},
            # Longest prefix wins: allow /16 beats allow /8.
            {"decision": "allow", "matched_cidr": "10.1.0.0/16",
             "matched_side": "allow"},
            # Equal prefix length (/8): deny beats allow.
            {"decision": "deny", "matched_cidr": "10.0.0.0/8",
             "matched_side": "deny"},
            {"decision": "allow", "matched_cidr": "2001:db8::/32",
             "matched_side": "allow"},
            {"decision": "unmatched", "matched_cidr": None,
             "matched_side": None},
        ]
    }


def test_evaluate_results_follow_address_order():
    # Output order mirrors the input addresses, families interleaved.
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/8", "2001:db8::/32"],
            "deny": [],
            "addresses": ["2001:db8::1", "10.0.0.1", "2001:db8::2"],
        },
    )
    assert response.status_code == 200
    assert [r["matched_cidr"] for r in response.json()["results"]] == [
        "2001:db8::/32", "10.0.0.0/8", "2001:db8::/32",
    ]


def test_evaluate_duplicate_entries_are_stable():
    # Identical duplicates in one list tie on every key; the first
    # occurrence wins, so duplicates never change the outcome.
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24", "10.0.0.0/24"],
            "deny": [],
            "addresses": ["10.0.0.7"],
        },
    )
    assert response.status_code == 200
    assert response.json()["results"] == [
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_bare_address_entries_are_host_prefixes():
    response = client.post(
        "/evaluate",
        json={
            "allow": ["10.0.0.0/24"],
            "deny": ["10.0.0.1"],
            "addresses": ["10.0.0.1", "10.0.0.2"],
        },
    )
    assert response.status_code == 200
    assert response.json()["results"] == [
        {"decision": "deny", "matched_cidr": "10.0.0.1/32",
         "matched_side": "deny"},
        {"decision": "allow", "matched_cidr": "10.0.0.0/24",
         "matched_side": "allow"},
    ]


def test_evaluate_empty_body_defaults_to_empty_lists():
    response = client.post("/evaluate", json={})
    assert response.status_code == 200
    assert response.json() == {"results": []}


def test_evaluate_invalid_address_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": [], "deny": [], "addresses": ["10.0.0.1", "bogus"]},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert any(err["loc"][-1] == "addresses" for err in detail)


def test_evaluate_address_with_prefix_returns_422():
    response = client.post("/evaluate", json={"addresses": ["10.0.0.1/32"]})
    assert response.status_code == 422
    assert any(err["loc"][-1] == "addresses"
               for err in response.json()["detail"])


def test_evaluate_invalid_cidr_returns_422():
    response = client.post(
        "/evaluate",
        json={"allow": ["10.0.0.1/24"], "addresses": ["10.0.0.1"]},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "allow" for err in response.json()["detail"])


def test_evaluate_wrong_address_type_returns_422():
    response = client.post("/evaluate", json={"addresses": [10]})
    assert response.status_code == 422


def test_evaluate_openapi_examples_present():
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]
    assert schemas["EvaluateRequest"]["examples"]
    assert schemas["EvaluateResponse"]["examples"]
    assert schemas["EvaluateRequest"]["properties"]["addresses"]["examples"]
