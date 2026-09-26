"""Assemble the full per-image forensic report: metadata + tamper flags +
OCR'd text (classified by the sibling phishing model) + any QR codes
(decoded and risk-scored)."""

import json

from . import ocr, qr_scanner, scam_bridge
from .metadata_extractor import analyze_image

# These two flag types are surfaced for the investigator's awareness but are
# too common in ordinary, non-tampered images (every screenshot lacks EXIF;
# plenty of real photos carry GPS) to count toward the headline "FLAGGED"
# verdict on their own.
INFORMATIONAL_ONLY_FLAGS = {"no_exif_data", "gps_present"}


def build_report(image_path: str) -> dict:
    forensic = analyze_image(image_path).to_dict()

    ocr_text = ocr.extract_text(image_path)
    text_classification = scam_bridge.classify_extracted_text(ocr_text) if ocr_text else {
        "skipped": True, "reason": "no text detected in image",
    }

    qr_payloads = qr_scanner.decode_qr_codes(image_path)
    qr_results = []
    for payload in qr_payloads:
        entry = {"payload": payload}
        if qr_scanner.is_url(payload):
            entry["url_analysis"] = qr_scanner.analyze_url(payload)
        else:
            entry["text_classification"] = scam_bridge.classify_extracted_text(payload)
        qr_results.append(entry)

    overall_signals = []
    notable_flags = [f for f in forensic["red_flags"] if f["flag"] not in INFORMATIONAL_ONLY_FLAGS]
    if notable_flags:
        overall_signals.append(
            f"{len(notable_flags)} notable metadata red flag(s): "
            f"{', '.join(f['flag'] for f in notable_flags)}"
        )
    if not text_classification.get("skipped") and text_classification.get("label") == "spam":
        overall_signals.append(f"OCR'd text classified as SPAM (p={text_classification['proba_spam']:.2f})")
    for qr in qr_results:
        if qr.get("url_analysis", {}).get("verdict") in ("medium_risk", "high_risk"):
            overall_signals.append(f"QR code URL is {qr['url_analysis']['verdict']}: {qr['payload']}")
        if qr.get("text_classification", {}).get("label") == "spam":
            overall_signals.append("QR code payload text classified as SPAM")

    return {
        "metadata_forensics": forensic,
        "ocr": {"text": ocr_text, "classification": text_classification},
        "qr_codes": qr_results,
        "overall_signals": overall_signals,
        "flagged": bool(overall_signals),
    }


def format_report(report: dict) -> str:
    lines = []
    meta = report["metadata_forensics"]
    lines.append(f"File: {meta['file_path']}")
    lines.append(f"  Format: {meta['image_format']}  Size: {meta['image_size']}  "
                 f"{meta['file_size_bytes']} bytes")
    lines.append(f"  SHA256: {meta['sha256']}")
    lines.append(f"  EXIF present: {meta['has_exif']}")
    if meta["exif"]:
        for k, v in meta["exif"].items():
            lines.append(f"    {k}: {v}")

    if meta["red_flags"]:
        lines.append("  Forensic red flags:")
        for flag in meta["red_flags"]:
            lines.append(f"    [{flag['flag']}] {flag['detail']}")
            lines.append(f"      note: {flag['note']}")
    else:
        lines.append("  Forensic red flags: none")

    ocr_block = report["ocr"]
    if ocr_block["text"]:
        lines.append(f"  OCR text: {ocr_block['text'][:200]!r}")
        cls = ocr_block["classification"]
        if not cls.get("skipped"):
            lines.append(f"    Classified: {cls['label'].upper()} (P(spam)={cls['proba_spam']:.3f})")
            if cls["signals_fired"]:
                lines.append(f"    Signals: {', '.join(cls['signals_fired'])}")
        else:
            lines.append(f"    (not classified: {cls['reason']})")
    else:
        lines.append("  OCR text: none detected")

    if report["qr_codes"]:
        lines.append("  QR codes found:")
        for qr in report["qr_codes"]:
            lines.append(f"    Payload: {qr['payload']}")
            if "url_analysis" in qr:
                ua = qr["url_analysis"]
                lines.append(f"      Verdict: {ua['verdict']} (score={ua['risk_score']})")
                for sig in ua["signals"]:
                    lines.append(f"        - {sig}")
            elif "text_classification" in qr and not qr["text_classification"].get("skipped"):
                tc = qr["text_classification"]
                lines.append(f"      Classified: {tc['label'].upper()} (P(spam)={tc['proba_spam']:.3f})")
    else:
        lines.append("  QR codes found: none")

    lines.append("")
    if report["flagged"]:
        lines.append(f"OVERALL: FLAGGED - {'; '.join(report['overall_signals'])}")
    else:
        lines.append("OVERALL: no scam/tamper signals detected")

    return "\n".join(lines)


def report_to_json(report: dict) -> str:
    return json.dumps(report, indent=2, default=str)
