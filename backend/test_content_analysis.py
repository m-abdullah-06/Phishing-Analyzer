from email import message_from_string

from content_analysis import analyze_content, analyze_esp


def test_shipping_notification_is_normal_context_not_social_engineering():
    result = analyze_content("Your order has shipped", "Your package is on the way. Track delivery.")

    assert result["risk_contribution"] == 0
    assert "shipping_notification" in result["normal_patterns"]


def test_high_pressure_password_request_is_substantially_suspicious():
    result = analyze_content("Urgent account alert", "Your account will be permanently deleted in 10 minutes. Verify your password.")

    assert result["high_pressure_credential"] is True
    assert result["risk_contribution"] >= 30


def test_esp_is_only_credited_when_independently_corrobated():
    msg = message_from_string("X-SG-EID: example\nList-Unsubscribe: <https://example.com/unsubscribe>\nContent-Type: multipart/alternative; boundary=b\n\n--b\nContent-Type: text/html\n\n<p>Newsletter</p>\n--b--")
    result = analyze_esp(
        msg,
        [{"domain": "sendgrid.net"}, {"domain": "list-manage.example.com"}],
        {"dmarc": {"state": "PASS"}},
        {"findings": []},
        {"normal_patterns": ["newsletter"], "high_pressure_credential": False},
        {"multipart": True},
    )

    assert result["strong_legitimacy"] is True
    assert result["risk_contribution"] < 0


def test_esp_header_alone_never_marks_a_message_safe():
    msg = message_from_string("X-SG-EID: example\n\nVerify your password immediately")
    result = analyze_esp(
        msg, [], {"dmarc": {"state": "NONE"}}, {"findings": [{"code": "brand_impersonation"}]},
        {"normal_patterns": [], "high_pressure_credential": True}, {"multipart": False},
    )

    assert result["providers"] == ["SendGrid"]
    assert result["strong_legitimacy"] is False
    assert result["risk_contribution"] == 0
