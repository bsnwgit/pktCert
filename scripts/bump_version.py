#!/usr/bin/env python3
"""
Bump this app's VERSION file per the pkt* suite versioning rule:

    vMajor.Minor.Patch.CodeName[.Hotfix]

- Major/Minor/Patch bump at a normal pace based on the applied update.
- CodeName is a randomly generated word, regenerated on every commit.
- Hotfix is a random 6-digit number, present only for hotfix commits.

This is a manual step run as part of the normal commit workflow — not a
git hook, not CI-triggered.

Usage:
    python3 scripts/bump_version.py            # codename refresh only
    python3 scripts/bump_version.py --major
    python3 scripts/bump_version.py --minor
    python3 scripts/bump_version.py --patch
    python3 scripts/bump_version.py --patch --hotfix
"""
import argparse
import random
from pathlib import Path

VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"

CODENAMES = [
    "ember", "quartz", "falcon", "cobalt", "tundra", "cipher", "nimbus", "onyx",
    "raven", "sable", "cinder", "basalt", "argon", "krypton", "zephyr", "borealis",
    "meridian", "obelisk", "granite", "opal", "jasper", "flint", "amber", "slate",
    "vertex", "helix", "pulsar", "quasar", "comet", "nova", "eclipse", "aurora",
    "glacier", "canyon", "summit", "ridge", "delta", "harbor", "lighthouse", "beacon",
    "compass", "anchor", "voyager", "drift", "current", "tide", "horizon", "prairie",
    "thicket", "birch", "cedar", "willow", "maple", "aspen", "juniper", "sequoia",
    "talon", "osprey", "kestrel", "harrier", "condor", "heron", "egret", "plover",
    "otter", "badger", "lynx", "bison", "elk", "wren", "finch", "sparrow",
    "copper", "bronze", "iron", "tin", "nickel", "zinc", "titanium", "tungsten",
    "indigo", "violet", "crimson", "scarlet", "umber", "ochre", "russet", "sepia",
    "cascade", "torrent", "geyser", "fjord", "delta", "atoll", "lagoon", "reef",
    "monolith", "citadel", "bastion", "rampart", "parapet", "turret", "spire", "keep",
    "kestrel", "gyrfalcon", "merlin", "peregrine", "sable", "marten", "ferret", "stoat",
]


def read_version() -> tuple[int, int, int]:
    if VERSION_FILE.exists():
        parts = VERSION_FILE.read_text().strip().split(".")
        if len(parts) >= 3:
            return int(parts[0]), int(parts[1]), int(parts[2])
    return 0, 1, 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--major", action="store_true")
    ap.add_argument("--minor", action="store_true")
    ap.add_argument("--patch", action="store_true")
    ap.add_argument("--hotfix", action="store_true")
    args = ap.parse_args()

    major, minor, patch = read_version()
    if args.major:
        major += 1
        minor = 0
        patch = 0
    elif args.minor:
        minor += 1
        patch = 0
    elif args.patch:
        patch += 1

    codename = random.choice(CODENAMES)
    version = f"{major}.{minor}.{patch}.{codename}"
    if args.hotfix:
        version += f".{random.randint(0, 999999):06d}"

    VERSION_FILE.write_text(version + "\n")
    print(f"Version bumped to {version}")


if __name__ == "__main__":
    main()
