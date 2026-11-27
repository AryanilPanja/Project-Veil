"""HUMAN-ONLY spike for sanitize-and-paste (M3.5, ADR-0030): can veil press keys for you through
the XDG desktop portal, how slow is it, and does KDE remember your "yes"?

It types into whatever window has focus, so agents must never run it (denied in
.claude/settings.json). It never reads the clipboard or the persona.

    uv run python scripts/paste_spike.py                  # types "veil" after 3 s
    uv run python scripts/paste_spike.py --paste ctrl+v   # presses Ctrl+V instead
    uv run python scripts/paste_spike.py --forget         # forget the remembered permission

Run it three times: (1) KDE asks: tick "remember" and allow; (2) right after: it should NOT ask;
(3) after a reboot: does it ask again? Each run prints the timings to report back.
"""

import argparse
import sys
import time

from veil import paths
from veil.clip import portal


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wait", type=float, default=3.0, help="seconds to focus a window")
    parser.add_argument("--paste", choices=sorted(portal.CHORDS), help="press this chord instead")
    parser.add_argument("--forget", action="store_true", help="delete the remembered permission")
    args = parser.parse_args()

    config = paths.config_dir()
    if args.forget:
        portal.save_token(config, None)
        print("forgot the remembered permission")
        return 0

    token = portal.load_token(config)
    print(f"remembered permission: {'yes' if token else 'no'}")
    keyboard = portal.RemoteKeyboard()
    total = time.monotonic()
    try:
        new_token = keyboard.open(token)
        portal.save_token(config, new_token)
        opened = time.monotonic() - total
        remembered = "yes" if new_token else "no"
        print(f"session open in {opened * 1000:.0f} ms; new permission token: {remembered}")
        print(f"focus the window to type into: {args.wait:.0f} s ...")
        time.sleep(args.wait)
        if args.paste:
            keyboard.press(portal.CHORDS[args.paste])
        else:
            for letter in "veil":
                keyboard.press([ord(letter)])
    except portal.Refused as exc:
        print(f"refused: {exc}")
        return 1
    except portal.PortalError as exc:
        print(f"portal error: {exc}")
        return 2
    finally:
        keyboard.close()
    for step, seconds in keyboard.timings.items():
        print(f"  {step:<7} {seconds * 1000:7.0f} ms")
    asked = keyboard.timings.get("start", 0) > 0.8
    shown = "probably yes" if asked else "no"
    print(f"dialog shown: {shown} (Start took over 0.8 s = it waited for you)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
