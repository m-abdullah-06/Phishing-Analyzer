import auth_checker


def _auth_result(state, aligned=False, domain=None):
    return {
        "state": state,
        "alignment": {"aligned": aligned, "domain": domain},
    }


def test_relaxed_alignment_accepts_subdomain():
    assert auth_checker._domains_align("mailer.example.com", "example.com")
    assert not auth_checker._domains_align("mailer.example.net", "example.com")


def test_dmarc_pass_requires_passing_aligned_auth(monkeypatch):
    monkeypatch.setattr(auth_checker, "_query_txt", lambda _: ["v=DMARC1; p=none"])

    result = auth_checker.check_dmarc(
        "example.com",
        _auth_result("PASS", aligned=True, domain="mailer.example.com"),
        _auth_result("PASS", aligned=True, domain="example.com"),
    )

    assert result["state"] == "PASS"
    assert result["impact"]["risk_contribution"] == 0
    assert result["alignment"]["spf_aligned"] is True
    assert result["alignment"]["dkim_aligned"] is True


def test_dmarc_policy_is_not_a_pass_without_aligned_auth(monkeypatch):
    monkeypatch.setattr(auth_checker, "_query_txt", lambda _: ["v=DMARC1; p=reject"])

    result = auth_checker.check_dmarc(
        "example.com",
        _auth_result("PASS", aligned=False, domain="sender.other.example"),
        _auth_result("PASS", aligned=False, domain="signer.other.example"),
    )

    assert result["state"] == "FAIL"
    assert result["impact"]["risk_contribution"] == 10


def test_dmarc_none_is_distinct_from_dmarc_fail(monkeypatch):
    monkeypatch.setattr(auth_checker, "_query_txt", lambda _: [])

    result = auth_checker.check_dmarc("example.com", _auth_result("FAIL"), _auth_result("FAIL"))

    assert result["state"] == "NONE"
    assert result["impact"]["risk_contribution"] == 0
