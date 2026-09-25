from src.features import explain_signals, extract_handcrafted_features


def test_url_detection():
    feats = extract_handcrafted_features(["Click here: http://scam.com/verify"])
    assert feats[0][2] == 1.0  # has_url


def test_no_url_for_plain_text():
    feats = extract_handcrafted_features(["Kamusta, tara kain later"])
    assert feats[0][2] == 0.0


def test_ph_phone_number_detection():
    feats = extract_handcrafted_features(["Call us at 09171234567 now"])
    assert feats[0][9] >= 1  # num_phone_numbers


def test_urgency_word_matching():
    signals = explain_signals("URGENT: verify your account or it will be suspended")
    assert "urgent" in signals["matched_urgency_words"]
    assert "verify" in signals["matched_urgency_words"]
    assert "suspended" in signals["matched_urgency_words"]


def test_ph_keyword_matching():
    signals = explain_signals("Your GCash account needs OTP verification")
    assert "gcash" in signals["matched_ph_keywords"]
    assert "otp" in signals["matched_ph_keywords"]


def test_empty_text_does_not_crash():
    feats = extract_handcrafted_features([""])
    assert feats.shape == (1, 12)


def test_shortened_url_detection():
    feats = extract_handcrafted_features(["Claim here: bit.ly/xyz123"])
    assert feats[0][3] == 1.0  # has_shortened_url
