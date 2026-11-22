"""Verify a JSON evidence file exported by the analyzer.

Usage:  python verify_evidence.py url-evidence-xxxx.json
"""
import json
import sys

from analyzer.scoring import evidence_hash

with open(sys.argv[1], encoding="utf-8") as fh:
    record = json.load(fh)

expected = record["integrity"]["evidence_hash"]
actual = evidence_hash(record)
print(f"Recorded hash : {expected}\nComputed hash : {actual}")
print("RESULT: INTACT" if actual == expected else "RESULT: MODIFIED - evidence does not match its hash")
sys.exit(0 if actual == expected else 1)
