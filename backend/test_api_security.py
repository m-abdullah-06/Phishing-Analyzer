import pytest
from starlette.datastructures import Headers
from starlette.requests import Request

import main


def test_validate_email_bytes_rejects_plain_text():
    with pytest.raises(main.HTTPException) as exc:
        main.validate_email_bytes(b"hello world")
    assert exc.value.status_code == 400


def test_require_api_key_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(main, "API_KEY", "top-secret")
    request = Request({
        "type": "http",
        "headers": [(b"x-api-key", b"wrong-key")],
        "method": "POST",
        "path": "/api/v1/analyze",
        "query_string": b"",
    })

    with pytest.raises(main.HTTPException) as exc:
        main.require_api_key(request)
    assert exc.value.status_code == 401


def test_enforce_rate_limit_blocks_excess_requests(monkeypatch):
    monkeypatch.setattr(main, "RATE_LIMIT_MAX_REQUESTS", 2)
    monkeypatch.setattr(main, "RATE_LIMIT_WINDOW_SECONDS", 60)
    main._RATE_LIMIT_BUCKETS.clear()

    for _ in range(2):
        main.enforce_rate_limit("203.0.113.10")

    with pytest.raises(main.HTTPException) as exc:
        main.enforce_rate_limit("203.0.113.10")
    assert exc.value.status_code == 429
