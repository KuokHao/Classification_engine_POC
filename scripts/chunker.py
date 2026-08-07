"""
Chunk text produced by src/services/htmlAnalyzer.js.

Two-level split:
  1) Keep each zone string separate (heading vs paragraph never merge).
  2) Inside a long zone, slide a word window (default 8 / step 4).

Tokenization is whitespace-only. Non-English pages are translated to English
upstream (languageTranslater) before chunking.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# Prefer reading-order zones when textZones is present
ZONE_ORDER = (
    ("titleText", "title"),
    ("iframeText", "iframe"),  # captured iframe body (often primary page content)
    ("headingText", "heading"),
    ("paragraphText", "paragraph"),
    ("buttonText", "button"),
    ("linkText", "link"),
    ("labelText", "label"),
    ("placeholderText", "placeholder"),
    ("footerText", "footer"),
    ("imageAltText", "imageAlt"),
    ("formNearbyText", "formNearby"),
)


def sliding_window_chunker(
    text: str,
    window_size: int = 8,
    step_size: int = 4,
) -> list[str]:
    """
    Sliding window over words (not characters). O(n) in token count.

    Example:
        sliding_window_chunker(
            "Critical security alert Action required claim cash now",
            window_size=8,
            step_size=4,
        )
    """
    # Robust guards — invalid sizes or empty input produce no chunks
    if window_size < 1 or step_size < 1:
        return []
    if not isinstance(text, str) or not text.strip():
        return []

    # Whitespace path: collapses newlines/tabs/multi-spaces
    words = text.split()
    if not words:
        return []

    # Short zone (typical heading / button) — keep as a single chunk
    if len(words) <= window_size:
        return [" ".join(words)]

    chunks: list[str] = []
    # Slide forward by step_size; last window may be shorter than window_size
    for i in range(0, len(words), step_size):
        chunks.append(" ".join(words[i : i + window_size]))
        if i + window_size >= len(words):
            break
    return chunks


def _docs_from_zones(text_zones: dict[str, Any]) -> list[tuple[str, dict]]:
    """Flatten textZones into (text, metadata) pairs — one unit per element string."""
    docs: list[tuple[str, dict]] = []

    for field, zone in ZONE_ORDER:
        value = text_zones.get(field)
        if isinstance(value, str) and value.strip():
            docs.append((value.strip(), {"zone": zone}))
        elif isinstance(value, list):
            for item in value:
                piece = str(item).strip()
                if piece:
                    docs.append((piece, {"zone": zone}))

    return docs


def _docs_from_visible_text(visible_text: list[str] | str) -> list[tuple[str, dict]]:
    """Fallback when textZones are missing: one unit per visibleText entry."""
    if isinstance(visible_text, str):
        parts = [visible_text.strip()] if visible_text.strip() else []
    else:
        parts = [str(p).strip() for p in visible_text if str(p).strip()]
    # Keep entries separate so we do not glue unrelated blocks before sliding
    return [(p, {"zone": "visibleText"}) for p in parts]


def smart_text_chunker(
    payload: dict[str, Any] | str | list[str],
    window_size: int = 8,
    step_size: int = 4,
) -> list[dict[str, Any]]:
    """
    Chunk htmlAnalyzer output into embedding-ready pieces.

    Accepts:
      - analyzeHtml() object / { visibleText, textZones }
      - a plain string / string list
    """
    if isinstance(payload, (str, list)):
        docs = _docs_from_visible_text(payload)
    elif isinstance(payload, dict):
        zones = payload.get("textZones")
        if isinstance(zones, dict) and any(zones.get(f) for f, _ in ZONE_ORDER):
            docs = _docs_from_zones(zones)
        elif "visibleText" in payload:
            docs = _docs_from_visible_text(payload["visibleText"])
        elif isinstance(payload.get("text"), str):
            docs = _docs_from_visible_text(payload["text"])
        else:
            docs = []
    else:
        raise TypeError("payload must be a dict, str, or list of str")

    if not docs:
        return []

    # Per-zone slide only — never merge h1 text with a following paragraph
    results: list[dict[str, Any]] = []
    for text, metadata in docs:
        for piece in sliding_window_chunker(
            text,
            window_size=window_size,
            step_size=step_size,
        ):
            results.append({"text": piece, "metadata": dict(metadata)})

    return results


def main() -> None:
    """Read htmlAnalyzer JSON from stdin; write chunks JSON to stdout."""
    raw = sys.stdin.read()
    if not raw.strip():
        print("[]")
        return

    payload = json.loads(raw)
    chunks = smart_text_chunker(payload)
    json.dump(chunks, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
