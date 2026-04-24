#!/usr/bin/env python3
"""
ssid_wordgen - SSID-Based Wordlist Generator for wpa_bruter demos

Generates a small, targeted wordlist derived from an SSID by applying
common password patterns that lazy admins and default configs tend to use.
Designed as a companion to wpa_bruter for classroom demonstrations.

Usage:
  python3 ssid_wordgen.py "ICTAK-Guest"
  python3 ssid_wordgen.py "ICTAK-Guest" -o demo_words.txt
  python3 ssid_wordgen.py "ICTAK-Guest" --show

Before a demo, pick one of the generated passwords, set it on your AP,
then run wpa_bruter against it with the generated wordlist.

Author : Built with Claude for ICTAK CSA/Wireless Security training
License: MIT
"""

import argparse
import itertools
import os
import sys
from pathlib import Path


# ─── Terminal Colors ──────────────────────────────────────────────────────────

class C:
    G  = '\033[92m'
    Y  = '\033[93m'
    B  = '\033[94m'
    CY = '\033[96m'
    BD = '\033[1m'
    DM = '\033[2m'
    RS = '\033[0m'


# ─── Pattern Engine ───────────────────────────────────────────────────────────

# Common suffixes people append to SSID-based passwords
NUMERIC_SUFFIXES = [
    "123", "1234", "12345", "321", "111", "000",
    "786", "007", "999", "2024", "2025", "2026",
    "01", "10", "99", "11", "22",
]

SYMBOL_NUMERIC_SUFFIXES = [
    "@123", "@1234", "@12345", "@321",
    "#123", "#1234", "#321",
    "!123", "!1234",
    "@1", "@12", "@01",
    "#1", "#12",
    "@786", "#786",
    "@2024", "@2025", "@2026",
    "!1", "$123",
    "@007", "#007",
    "_123", "_1234",
]

# Common words appended or used with SSID
COMMON_WORDS = [
    "password", "pass", "admin", "wifi", "guest",
    "secure", "net", "connect", "welcome",
]

WORD_SUFFIXES = [
    "@123", "@1234", "#123", "123", "1234", "!123", "",
]

# Leet speak substitutions
LEET_MAP = {
    'a': '4', 'e': '3', 'i': '1', 'o': '0',
    's': '5', 't': '7', 'l': '1', 'b': '8',
}


def generate_case_variants(text: str) -> list[str]:
    """Generate common casing variants of a string."""
    variants = set()
    variants.add(text)                    # as-is
    variants.add(text.lower())            # all lower
    variants.add(text.upper())            # all upper
    variants.add(text.capitalize())       # first cap
    variants.add(text.title())            # title case
    variants.add(text.swapcase())         # swapped
    # First letter lower, rest as-is
    if len(text) > 1:
        variants.add(text[0].lower() + text[1:])
    return list(variants)


def leet_speak(text: str) -> str:
    """Convert text to basic leet speak."""
    return ''.join(LEET_MAP.get(c.lower(), c) for c in text)


def extract_parts(ssid: str) -> dict:
    """
    Break SSID into useful components.
    e.g. "ICTAK-Guest" -> base="ICTAK-Guest", parts=["ICTAK", "Guest"],
         stripped="ICTAKGuest", initials="IG"
    """
    # Split on common delimiters
    import re
    parts = re.split(r'[-_ .]+', ssid)
    parts = [p for p in parts if p]  # remove empties

    return {
        "full": ssid,
        "parts": parts,
        "stripped": ''.join(parts),                       # no delimiters
        "initials": ''.join(p[0] for p in parts if p),   # first letters
        "reversed": ssid[::-1],
        "first": parts[0] if parts else ssid,
        "last": parts[-1] if len(parts) > 1 else "",
    }


def generate_wordlist(ssid: str) -> list[str]:
    """Generate all candidate passwords from an SSID."""
    candidates = set()
    info = extract_parts(ssid)

    # ── Category 1: SSID as-is + numeric/symbol suffixes ──
    # The most common pattern: SSID@123, SSID#1234, etc.
    for base in [info["full"], info["stripped"]]:
        for variant in generate_case_variants(base):
            # Plain (only if >= 8 chars, WPA minimum)
            candidates.add(variant)

            for suffix in NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)

            for suffix in SYMBOL_NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)

    # ── Category 2: Individual parts + suffixes ──
    # e.g. "ICTAK@123", "Guest@1234"
    for part in info["parts"]:
        for variant in generate_case_variants(part):
            candidates.add(variant)
            for suffix in NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)
            for suffix in SYMBOL_NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)

    # ── Category 3: Part combinations with different separators ──
    # e.g. "ICTAK_Guest", "ictak.guest", "ICTAK@Guest"
    if len(info["parts"]) >= 2:
        for sep in ["-", "_", ".", "@", "#", ""]:
            combined = sep.join(info["parts"])
            for variant in generate_case_variants(combined):
                candidates.add(variant)
                for suffix in SYMBOL_NUMERIC_SUFFIXES[:8]:  # top suffixes
                    candidates.add(variant + suffix)

    # ── Category 4: Initials-based ──
    # e.g. "IG@1234"
    initials = info["initials"]
    if len(initials) >= 2:
        for variant in generate_case_variants(initials):
            for suffix in SYMBOL_NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)
            for suffix in NUMERIC_SUFFIXES:
                candidates.add(variant + suffix)

    # ── Category 5: Common word combinations ──
    # e.g. "ICTAKpassword", "ICTAKadmin123", "ICTAK_wifi"
    for part in [info["first"], info["full"]]:
        for word in COMMON_WORDS:
            for sep in ["", "_", "@", "#"]:
                combo = part + sep + word
                for variant in generate_case_variants(combo):
                    candidates.add(variant)
                    for suffix in ["", "123", "1234", "@123", "!"]:
                        candidates.add(variant + suffix)
                # Also reversed: word + SSID part
                combo_r = word + sep + part
                candidates.add(combo_r)
                candidates.add(combo_r + "123")
                candidates.add(combo_r + "@123")

    # ── Category 6: Leet speak variants ──
    for base in [info["full"], info["stripped"], info["first"]]:
        l = leet_speak(base)
        if l != base.lower():  # only if leet actually changed something
            candidates.add(l)
            for suffix in SYMBOL_NUMERIC_SUFFIXES[:6]:
                candidates.add(l + suffix)

    # ── Category 7: Reversed ──
    rev = info["reversed"]
    candidates.add(rev)
    candidates.add(rev + "123")
    candidates.add(rev + "@123")

    # ── Category 8: Repeated SSID / stutter patterns ──
    first = info["first"]
    candidates.add(first + first)
    candidates.add(first.lower() + first.lower())
    candidates.add(first + first + "123")

    # ── Category 9: Keyboard-walk style defaults ──
    # Some admins just use these regardless of SSID
    generic = [
        "password", "Password", "password1", "Password1",
        "password123", "Password123", "Password@123",
        "admin123", "Admin@123", "admin@123",
        "welcome1", "Welcome1", "Welcome@123",
        "12345678", "123456789", "1234567890",
        "87654321", "00000000", "11111111",
        "qwerty123", "Qwerty@123", "qwertyuiop",
        "abcd1234", "Abcd@1234", "abcdefgh",
        "iloveyou", "letmein1", "changeme",
        "passw0rd", "P@ssw0rd", "P@ssword1",
    ]
    candidates.update(generic)

    # ── Filter: WPA requires 8-63 characters ──
    valid = sorted(
        {p for p in candidates if 8 <= len(p) <= 63},
        key=lambda x: (len(x), x),
    )

    return valid


def generate_quick_wordlist(ssid: str, count: int = 20) -> list[str]:
    """
    Generate a tiny, high-probability wordlist for quick demos.
    These are the patterns admins most commonly use.
    """
    info = extract_parts(ssid)
    candidates = []

    # The top patterns, roughly in order of real-world likelihood
    top_suffixes = ["@123", "@1234", "@321", "#123", "!123",
                    "123", "1234", "@12345", "@786", "@007"]

    # Full SSID + suffixes (most common lazy pattern)
    for suffix in top_suffixes:
        candidates.append(info["full"] + suffix)

    # Lowercase SSID + suffixes
    for suffix in top_suffixes[:5]:
        candidates.append(info["full"].lower() + suffix)

    # First part only + suffixes
    if info["first"] != info["full"]:
        for suffix in top_suffixes[:5]:
            candidates.append(info["first"] + suffix)
            candidates.append(info["first"].lower() + suffix)

    # No-delimiter variant
    if info["stripped"] != info["full"]:
        for suffix in top_suffixes[:3]:
            candidates.append(info["stripped"] + suffix)
            candidates.append(info["stripped"].lower() + suffix)

    # Leet speak
    l = leet_speak(info["full"])
    if l != info["full"].lower():
        candidates.append(l + "@123")

    # Common generics that admins love
    candidates.extend([
        "password", "Password@123", "12345678",
        "admin@123", "P@ssw0rd",
    ])

    # Filter valid WPA length + deduplicate while preserving order
    seen = set()
    valid = []
    for p in candidates:
        if 8 <= len(p) <= 63 and p not in seen:
            seen.add(p)
            valid.append(p)

    return valid[:count]


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ssid_wordgen",
        description="Generate a targeted wordlist from a WiFi SSID for demos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""{C.DM}
Examples
────────
  # Full wordlist (thousands of candidates)
  python3 ssid_wordgen.py "ICTAK-Guest"

  # Quick mode — just ~20 top passwords for fast demos
  python3 ssid_wordgen.py "ICTAK-Guest" --quick

  # Quick mode with custom count
  python3 ssid_wordgen.py "ICTAK-Guest" --quick 15 -o demo.txt

  # Just print to screen
  python3 ssid_wordgen.py "ICTAK-Guest" --quick --show

  # Pipe directly into wpa_bruter
  python3 ssid_wordgen.py "ICTAK-Guest" --quick --show | \\
    sudo python3 wpa_bruter.py -i wlan0 -s "ICTAK-Guest" -b AA:BB:CC:DD:EE:FF -w /dev/stdin

Demo workflow
─────────────
  1. Run:  python3 ssid_wordgen.py "YourTestAP" --quick
  2. Pick one password from the generated list
  3. Set that password on your demo AP
  4. Run:  sudo python3 wpa_bruter.py -i wlan0 -s "YourTestAP" -b <bssid> -w YourTestAP_wordlist.txt
  5. Watch it crack in front of the class
{C.RS}""",
    )

    parser.add_argument("ssid",
                        help="The SSID to generate passwords from")
    parser.add_argument("-o", "--output", default=None,
                        metavar="FILE",
                        help="Output file (default: <ssid>_wordlist.txt)")
    parser.add_argument("--show", action="store_true",
                        help="Print wordlist to stdout instead of saving")
    parser.add_argument("--quick", type=int, default=0, nargs="?", const=20,
                        metavar="N",
                        help="Generate only top N most likely passwords "
                             "(default: 20). Ideal for quick demos.")
    parser.add_argument("--stats", action="store_true",
                        help="Show breakdown of generation categories")

    args = parser.parse_args()

    ssid = args.ssid

    if args.quick:
        words = generate_quick_wordlist(ssid, args.quick)
        mode_label = f"quick ({args.quick})"
    else:
        words = generate_wordlist(ssid)
        mode_label = "full"

    if args.show:
        for w in words:
            print(w)
        return

    # Determine output path
    if args.output:
        out_path = args.output
    else:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in ssid)
        out_path = f"{safe_name}_wordlist.txt"

    with open(out_path, "w") as f:
        f.write("\n".join(words) + "\n")

    # Summary
    print(f"\n  {C.CY}{C.BD}ssid_wordgen{C.RS}")
    print(f"  {'─' * 40}")
    print(f"  {C.BD}SSID       :{C.RS} {ssid}")
    print(f"  {C.BD}Mode       :{C.RS} {mode_label}")
    print(f"  {C.BD}Generated  :{C.RS} {len(words)} candidates")
    print(f"  {C.BD}Saved to   :{C.RS} {out_path}")
    print(f"  {C.BD}File size  :{C.RS} {os.path.getsize(out_path) / 1024:.1f} KB")
    print(f"  {'─' * 40}")

    # Show a sample
    print(f"\n  {C.DM}Sample passwords:{C.RS}")
    # Pick some interesting ones to display
    samples = []
    info = extract_parts(ssid)
    targets = [
        info["full"] + "@123",
        info["full"].lower() + "@1234",
        info["first"] + "#123",
        info["full"] + "!123",
        info["stripped"].lower() + "@321",
        leet_speak(info["full"]) + "@123",
        info["first"] + "_" + "admin" + "123",
    ]
    for t in targets:
        if t in words and len(t) >= 8:
            samples.append(t)
    # Fill remainder from wordlist
    for w in words:
        if len(samples) >= 10:
            break
        if w not in samples and "@" in w:
            samples.append(w)

    for s in samples[:10]:
        print(f"    {C.G}•{C.RS} {s}")

    print(f"\n  {C.Y}Pick one of these, set it on your demo AP,")
    print(f"  then run wpa_bruter with the generated wordlist.{C.RS}\n")


if __name__ == "__main__":
    main()
