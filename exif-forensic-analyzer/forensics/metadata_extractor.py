"""EXIF/metadata extraction and tamper-indicator detection for images.

This is the forensics core: what an investigator actually looks at first
when handed an image isn't the pixels, it's the metadata sitting around
them — where and when it says the photo was taken, what device made it,
whether it's been through an editor, and whether the embedded thumbnail
(a leftover from the original capture) still matches the full image.

None of these signals prove tampering on their own (missing EXIF is also
just what every screenshot and every re-saved WhatsApp photo looks like),
which is why every flag below is reported with its caveat rather than as a
verdict — that's a deliberate design choice, not an omission.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import piexif
from PIL import Image

EDITING_SOFTWARE_MARKERS = [
    "photoshop", "gimp", "snapseed", "picsart", "lightroom",
    "affinity photo", "pixlr", "canva", "paint.net", "luminar",
]

DATETIME_MISMATCH_THRESHOLD_SECONDS = 24 * 3600  # 1 day


@dataclass
class ForensicReport:
    file_path: str
    file_size_bytes: int
    md5: str
    sha256: str
    image_format: Optional[str]
    image_size: Optional[tuple]
    has_exif: bool
    exif: dict = field(default_factory=dict)
    red_flags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "md5": self.md5,
            "sha256": self.sha256,
            "image_format": self.image_format,
            "image_size": self.image_size,
            "has_exif": self.has_exif,
            "exif": self.exif,
            "red_flags": self.red_flags,
        }


def compute_hashes(path: str) -> dict:
    data = Path(path).read_bytes()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00").strip()
    return str(value).strip()


def _rational_to_deg(rational_triplet) -> float:
    """Convert a piexif ((deg,1),(min,1),(sec,100))-style GPS rational
    triplet to decimal degrees."""
    deg = rational_triplet[0][0] / rational_triplet[0][1]
    minutes = rational_triplet[1][0] / rational_triplet[1][1]
    seconds = rational_triplet[2][0] / rational_triplet[2][1]
    return deg + minutes / 60 + seconds / 3600


def _extract_gps(gps_ifd: dict) -> Optional[dict]:
    if not gps_ifd:
        return None
    lat_data = gps_ifd.get(piexif.GPSIFD.GPSLatitude)
    lat_ref = gps_ifd.get(piexif.GPSIFD.GPSLatitudeRef)
    lon_data = gps_ifd.get(piexif.GPSIFD.GPSLongitude)
    lon_ref = gps_ifd.get(piexif.GPSIFD.GPSLongitudeRef)
    if not (lat_data and lon_data):
        return None

    lat = _rational_to_deg(lat_data)
    lon = _rational_to_deg(lon_data)
    if _decode(lat_ref) == "S":
        lat = -lat
    if _decode(lon_ref) == "W":
        lon = -lon
    return {"latitude": round(lat, 6), "longitude": round(lon, 6)}


def _parse_exif_datetime(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
    except (ValueError, TypeError):
        return None


def _average_hash(image: Image.Image, hash_size: int = 8) -> int:
    """Simple perceptual hash: resize to hash_size x hash_size grayscale,
    threshold each pixel against the mean. Good enough to detect "these
    two images are clearly different", which is all we need to compare a
    thumbnail against its supposed parent image."""
    small = image.convert("L").resize((hash_size, hash_size), Image.LANCZOS)
    pixels = list(small.getdata())
    avg = sum(pixels) / len(pixels)
    bits = "".join("1" if p > avg else "0" for p in pixels)
    return int(bits, 2)


def _hamming_distance(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def extract_exif(path: str) -> dict:
    """Return a flat, human-readable dict of EXIF fields. Empty dict if
    the file has no EXIF block (e.g. most PNGs, most screenshots, images
    re-saved by messaging apps that strip metadata)."""
    try:
        exif_dict = piexif.load(path)
    except Exception:
        return {}

    zeroth = exif_dict.get("0th", {})
    exif_ifd = exif_dict.get("Exif", {})
    gps_ifd = exif_dict.get("GPS", {})

    if not zeroth and not exif_ifd and not gps_ifd:
        return {}

    fields = {}
    if piexif.ImageIFD.Make in zeroth:
        fields["camera_make"] = _decode(zeroth[piexif.ImageIFD.Make])
    if piexif.ImageIFD.Model in zeroth:
        fields["camera_model"] = _decode(zeroth[piexif.ImageIFD.Model])
    if piexif.ImageIFD.Software in zeroth:
        fields["software"] = _decode(zeroth[piexif.ImageIFD.Software])
    if piexif.ImageIFD.DateTime in zeroth:
        fields["modify_date"] = _decode(zeroth[piexif.ImageIFD.DateTime])
    if piexif.ImageIFD.Orientation in zeroth:
        fields["orientation"] = zeroth[piexif.ImageIFD.Orientation]

    if piexif.ExifIFD.DateTimeOriginal in exif_ifd:
        fields["datetime_original"] = _decode(exif_ifd[piexif.ExifIFD.DateTimeOriginal])
    if piexif.ExifIFD.DateTimeDigitized in exif_ifd:
        fields["datetime_digitized"] = _decode(exif_ifd[piexif.ExifIFD.DateTimeDigitized])

    gps = _extract_gps(gps_ifd)
    if gps:
        fields["gps"] = gps

    thumbnail_bytes = exif_dict.get("thumbnail")
    fields["_has_thumbnail"] = thumbnail_bytes is not None
    fields["_thumbnail_bytes"] = thumbnail_bytes  # consumed by detect_red_flags, stripped before reporting

    return fields


def detect_red_flags(exif: dict, image: Image.Image) -> list:
    """Return a list of {flag, detail, note} dicts. Every flag includes a
    `note` explaining what it does and does NOT prove -- these are leads
    for a human investigator, not a verdict."""
    flags = []

    if not exif:
        flags.append({
            "flag": "no_exif_data",
            "detail": "No EXIF metadata block found.",
            "note": "Common for screenshots, PNGs, and images re-saved by "
                     "messaging apps (which strip metadata) -- not proof of "
                     "tampering by itself, but it does mean provenance "
                     "(device, original capture time, location) can't be "
                     "verified from this file alone.",
        })
        return flags

    software = exif.get("software", "").lower()
    for marker in EDITING_SOFTWARE_MARKERS:
        if marker in software:
            flags.append({
                "flag": "editing_software_present",
                "detail": f"Software tag: '{exif['software']}'",
                "note": "Confirms the file was processed by an editor at "
                         "some point. Does not indicate what was changed.",
            })
            break

    dt_original = _parse_exif_datetime(exif.get("datetime_original", ""))
    dt_modified = _parse_exif_datetime(exif.get("modify_date", ""))
    if dt_original and dt_modified:
        delta = abs((dt_modified - dt_original).total_seconds())
        if delta > DATETIME_MISMATCH_THRESHOLD_SECONDS:
            flags.append({
                "flag": "modify_date_after_capture_date",
                "detail": f"Captured {exif['datetime_original']}, modified "
                           f"{exif['modify_date']} ({delta / 3600:.1f}h apart)",
                "note": "The file was saved again well after the original "
                         "capture time -- consistent with editing, but also "
                         "consistent with simply re-exporting/re-saving "
                         "without changes.",
            })

    if "gps" in exif:
        flags.append({
            "flag": "gps_present",
            "detail": f"lat={exif['gps']['latitude']}, lon={exif['gps']['longitude']}",
            "note": "Not a tampering indicator -- flagged because embedded "
                     "location data is a real privacy/OPSEC concern if this "
                     "image is shared.",
        })

    thumbnail_bytes = exif.get("_thumbnail_bytes")
    if thumbnail_bytes:
        try:
            import io
            thumb_image = Image.open(io.BytesIO(thumbnail_bytes))
            distance = _hamming_distance(_average_hash(thumb_image), _average_hash(image))
            if distance > 20:  # out of 64 bits; empirically a large gap
                flags.append({
                    "flag": "thumbnail_mismatch",
                    "detail": f"Embedded thumbnail differs from the main image "
                               f"(perceptual hash distance {distance}/64)",
                    "note": "The embedded EXIF thumbnail is generated at "
                             "capture/edit time and normally matches the main "
                             "image. A large mismatch can mean the main image "
                             "was swapped or heavily edited after the "
                             "thumbnail was generated, or that metadata was "
                             "copied from a different file entirely.",
                })
        except Exception:
            pass

    return flags


def analyze_image(path: str) -> ForensicReport:
    hashes = compute_hashes(path)
    file_size = Path(path).stat().st_size

    with Image.open(path) as img:
        img.load()
        image_format = img.format
        image_size = img.size
        exif = extract_exif(path)
        red_flags = detect_red_flags(exif, img)

    exif_public = {k: v for k, v in exif.items() if not k.startswith("_")}
    if exif:
        exif_public["has_embedded_thumbnail"] = exif.get("_has_thumbnail", False)

    return ForensicReport(
        file_path=str(path),
        file_size_bytes=file_size,
        md5=hashes["md5"],
        sha256=hashes["sha256"],
        image_format=image_format,
        image_size=image_size,
        has_exif=bool(exif),
        exif=exif_public,
        red_flags=red_flags,
    )
