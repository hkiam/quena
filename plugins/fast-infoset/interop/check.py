#!/usr/bin/env python3
"""Interop check: decode every corpus/*.fi with Piper's decoder (several chunk
sizes) and compare the canonical XML (C14N 2.0) with the Java reference."""
import subprocess, sys, glob, os
from xml.etree.ElementTree import canonicalize

BIN = sys.argv[1]
ok = True
for fi in sorted(glob.glob(os.path.join(os.path.dirname(__file__), "corpus", "*.fi"))):
    exp = fi[:-3] + ".expected.xml"
    want = canonicalize(from_file=exp)
    size = os.path.getsize(fi)
    for chunk in ([1, 7, 65536] if size < 200_000 else [4093, 65536]):
        r = subprocess.run([BIN, fi, str(chunk)], capture_output=True)
        name = f"{os.path.basename(fi)} (chunk {chunk})"
        if r.returncode != 0:
            print(f"FAIL {name}: {r.stderr.decode()}")
            ok = False
            continue
        try:
            got = canonicalize(xml_data=r.stdout.decode("utf-8"))
        except Exception as e:
            print(f"FAIL {name}: output is not well-formed: {e}")
            ok = False
            continue
        if got != want:
            i = next((k for k in range(min(len(got), len(want))) if got[k] != want[k]), min(len(got), len(want)))
            print(f"FAIL {name}: differs at {i}\n  want …{want[max(0,i-80):i+80]!r}\n  got  …{got[max(0,i-80):i+80]!r}")
            ok = False
        else:
            print(f"ok   {name}")
sys.exit(0 if ok else 1)
