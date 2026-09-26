"""Generate synthetic test images for the forensic analyzer.

Everything here is generated from scratch with PIL/piexif/qrcode -- no real
photos, no real people, no real scam infrastructure. The point is to have
known-good/known-bad fixtures so the detector's behavior can be asserted in
tests rather than eyeballed.
"""

from pathlib import Path

import piexif
import qrcode
from PIL import Image, ImageDraw, ImageFont

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def _deg_to_dms_rational(deg_float: float):
    deg = int(deg_float)
    min_float = (deg_float - deg) * 60
    minute = int(min_float)
    sec_float = (min_float - minute) * 60
    sec = int(round(sec_float * 100))
    return ((deg, 1), (minute, 1), (sec, 100))


def _base_photo(color=(90, 130, 180)) -> Image.Image:
    img = Image.new("RGB", (640, 480), color=color)
    draw = ImageDraw.Draw(img)
    draw.ellipse((200, 140, 440, 340), fill=(230, 200, 120))
    draw.rectangle((0, 420, 640, 480), fill=(60, 90, 60))
    return img


def make_clean_photo():
    """A photo with realistic, internally-consistent EXIF: camera info,
    matching capture/modify dates, GPS, and a thumbnail that matches the
    main image -- i.e. no red flags should fire on this one."""
    img = _base_photo()
    path = FIXTURES_DIR / "clean_photo.jpg"

    zeroth = {
        piexif.ImageIFD.Make: b"Pixel",
        piexif.ImageIFD.Model: b"Pixel 7",
        piexif.ImageIFD.DateTime: b"2025:03:14 10:22:01",
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: b"2025:03:14 10:22:01",
        piexif.ExifIFD.DateTimeDigitized: b"2025:03:14 10:22:01",
    }
    gps_lat = _deg_to_dms_rational(14.5995)   # Manila
    gps_lon = _deg_to_dms_rational(120.9842)
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: b"N",
        piexif.GPSIFD.GPSLatitude: gps_lat,
        piexif.GPSIFD.GPSLongitudeRef: b"E",
        piexif.GPSIFD.GPSLongitude: gps_lon,
    }

    thumb = img.copy()
    thumb.thumbnail((160, 120))
    import io
    thumb_bytes_io = io.BytesIO()
    thumb.save(thumb_bytes_io, format="JPEG")

    exif_dict = {"0th": zeroth, "Exif": exif_ifd, "GPS": gps_ifd, "1st": {}, "thumbnail": thumb_bytes_io.getvalue()}
    exif_bytes = piexif.dump(exif_dict)
    img.save(path, "jpeg", exif=exif_bytes)
    return path


def make_edited_photo():
    """Same photo, but Software tag shows Photoshop and the modify date is
    several days after the capture date -- should trigger both
    editing_software_present and modify_date_after_capture_date."""
    img = _base_photo()
    path = FIXTURES_DIR / "edited_photo.jpg"

    zeroth = {
        piexif.ImageIFD.Make: b"Canon",
        piexif.ImageIFD.Model: b"EOS R6",
        piexif.ImageIFD.Software: b"Adobe Photoshop 25.0",
        piexif.ImageIFD.DateTime: b"2025:03:20 18:05:00",
    }
    exif_ifd = {
        piexif.ExifIFD.DateTimeOriginal: b"2025:03:14 10:22:01",
        piexif.ExifIFD.DateTimeDigitized: b"2025:03:14 10:22:01",
    }
    exif_dict = {"0th": zeroth, "Exif": exif_ifd, "GPS": {}, "1st": {}, "thumbnail": None}
    exif_bytes = piexif.dump(exif_dict)
    img.save(path, "jpeg", exif=exif_bytes)
    return path


def make_mismatched_thumbnail_photo():
    """EXIF present with an embedded thumbnail that depicts a completely
    different image than the main photo -- should trigger thumbnail_mismatch."""
    img = _base_photo(color=(90, 130, 180))
    path = FIXTURES_DIR / "mismatched_thumbnail_photo.jpg"

    unrelated_thumb = Image.new("RGB", (160, 120), color=(20, 20, 20))
    d = ImageDraw.Draw(unrelated_thumb)
    d.rectangle((10, 10, 150, 110), fill=(240, 240, 240))
    import io
    thumb_io = io.BytesIO()
    unrelated_thumb.save(thumb_io, format="JPEG")

    zeroth = {piexif.ImageIFD.Make: b"Generic", piexif.ImageIFD.Model: b"Camera"}
    exif_dict = {"0th": zeroth, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": thumb_io.getvalue()}
    exif_bytes = piexif.dump(exif_dict)
    img.save(path, "jpeg", exif=exif_bytes)
    return path


def make_stripped_screenshot():
    """A plain PNG with no EXIF at all -- realistic stand-in for a phone
    screenshot or a messaging-app re-save."""
    img = _base_photo(color=(240, 240, 245))
    path = FIXTURES_DIR / "stripped_screenshot.png"
    img.save(path, "png")
    return path


def make_phishing_screenshot():
    """Renders a fake SMS conversation bubble with phishing text, styled
    like a phone screenshot (no EXIF), so OCR + the phishing classifier
    have real text to work with."""
    img = Image.new("RGB", (600, 300), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(FONT_PATH, 20)

    draw.rounded_rectangle((20, 20, 580, 160), radius=15, fill=(0, 122, 255))
    message = (
        "GCash Alert: Your account will be\n"
        "suspended in 24 hours. Verify now:\n"
        "bit.ly/gcash-verify123"
    )
    draw.multiline_text((40, 40), message, font=font, fill=(255, 255, 255), spacing=8)

    path = FIXTURES_DIR / "phishing_screenshot.png"
    img.save(path, "png")
    return path


def make_legit_screenshot():
    """Same visual style, but an ordinary legitimate message -- should NOT
    be classified as spam."""
    img = Image.new("RGB", (600, 220), color=(245, 245, 245))
    draw = ImageDraw.Draw(img)
    font = ImageFont.truetype(FONT_PATH, 20)

    draw.rounded_rectangle((20, 20, 580, 130), radius=15, fill=(60, 180, 90))
    message = "Hey are we still on for\ncoffee tomorrow morning?"
    draw.multiline_text((40, 40), message, font=font, fill=(255, 255, 255), spacing=8)

    path = FIXTURES_DIR / "legit_screenshot.png"
    img.save(path, "png")
    return path


def make_qr_phishing():
    url = "http://gcash-verify-account.info/login"
    img = qrcode.make(url).convert("RGB")
    path = FIXTURES_DIR / "qr_phishing.png"
    img.save(path)
    return path, url


def make_qr_legit():
    url = "https://www.wikipedia.org"
    img = qrcode.make(url).convert("RGB")
    path = FIXTURES_DIR / "qr_legit.png"
    img.save(path)
    return path, url


def main():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    made = [
        make_clean_photo(),
        make_edited_photo(),
        make_mismatched_thumbnail_photo(),
        make_stripped_screenshot(),
        make_phishing_screenshot(),
        make_legit_screenshot(),
        make_qr_phishing()[0],
        make_qr_legit()[0],
    ]
    for path in made:
        print(f"Wrote {path}")


if __name__ == "__main__":
    main()
