"""OCR: pull any text rendered inside an image (e.g. a screenshotted SMS,
email, or chat message) so it can be fed to the phishing/scam classifier."""

from pathlib import Path

import pytesseract
from PIL import Image


def extract_text(image: "Image.Image | str") -> str:
    if isinstance(image, (str, Path)):
        image = Image.open(image)
    return pytesseract.image_to_string(image).strip()
