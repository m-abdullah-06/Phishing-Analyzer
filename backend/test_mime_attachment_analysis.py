from email_parser import analyze_mime, extract_attachments, parse_raw_email


def test_mime_anomaly_is_structural_not_phishing_label():
    raw = b"Content-Type: multipart/mixed; boundary=missing\r\n\r\n--missing\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
    result = analyze_mime(parse_raw_email(raw), raw)

    assert result["risk_contribution"] == 5
    assert result["detail"] == "Structural anomaly detected. Further investigation recommended."


def test_static_attachment_analysis_flags_pdf_executable_without_execution():
    raw = (
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        b"--b\r\nContent-Type: application/octet-stream; name=invoice.pdf.exe\r\n"
        b"Content-Disposition: attachment; filename=invoice.pdf.exe\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA\r\n--b--\r\n"
    )
    attachments = extract_attachments(parse_raw_email(raw))

    assert len(attachments) == 1
    assert attachments[0]["executable"] is True
    assert attachments[0]["suspicious_double_extension"] is True
    assert attachments[0]["mime_type"] == "application/octet-stream"
