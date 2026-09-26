from pathlib import Path

from forensics.metadata_extractor import analyze_image

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _flag_names(report):
    return {f["flag"] for f in report.red_flags}


def test_clean_photo_has_no_notable_flags():
    report = analyze_image(str(FIXTURES / "clean_photo.jpg"))
    assert report.has_exif
    assert report.exif["camera_make"] == "Pixel"
    assert report.exif["gps"] == {"latitude": 14.5995, "longitude": 120.9842}
    flags = _flag_names(report)
    assert "editing_software_present" not in flags
    assert "modify_date_after_capture_date" not in flags
    assert "thumbnail_mismatch" not in flags
    assert "gps_present" in flags  # informational, but should still be surfaced


def test_edited_photo_flags_software_and_datetime_mismatch():
    report = analyze_image(str(FIXTURES / "edited_photo.jpg"))
    flags = _flag_names(report)
    assert "editing_software_present" in flags
    assert "modify_date_after_capture_date" in flags


def test_mismatched_thumbnail_is_detected():
    report = analyze_image(str(FIXTURES / "mismatched_thumbnail_photo.jpg"))
    assert "thumbnail_mismatch" in _flag_names(report)


def test_stripped_screenshot_has_no_exif_flag():
    report = analyze_image(str(FIXTURES / "stripped_screenshot.png"))
    assert not report.has_exif
    assert _flag_names(report) == {"no_exif_data"}


def test_hashes_are_deterministic():
    report1 = analyze_image(str(FIXTURES / "clean_photo.jpg"))
    report2 = analyze_image(str(FIXTURES / "clean_photo.jpg"))
    assert report1.sha256 == report2.sha256
    assert len(report1.sha256) == 64
