#!/usr/bin/env python3
"""Merge CycloneDX JSON SBOMs into one SBOM for a Quena product.

  merge.py -o OUT --name quena --version 0.1.7 --platform linux-x64 \
      [--description TEXT] PART.json... [--plugin PLUGIN.json]...

Each part's main component (metadata.component) becomes a component of the product, which
depends on it; plugins are marked with the property quena:plugin. Components and dependencies
of all parts are merged by bom-ref, so a crate in the app and in a plugin is listed once, and
the two halves of the macOS universal build add up. Absolute paths of the checkout in
bom-refs and purls (cargo writes path+file:///<checkout>/crates/...) become relative to it.
SOURCE_DATE_EPOCH, when set, is the timestamp.
"""
import argparse
import datetime
import json
import os
import re
import sys
import uuid
from pathlib import Path

SPEC_VERSION = "1.5"
REPOSITORY = "https://github.com/hkiam/quena"


def fail(msg):
    print(f"merge.py: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            bom = json.load(f)
    except (OSError, ValueError) as e:
        fail(f"{path}: {e}")
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        fail(f"{path}: not a CycloneDX JSON SBOM")
    if not isinstance(bom.get("metadata", {}).get("component"), dict):
        fail(f"{path}: no metadata.component")
    return bom


def checkout_prefix():
    """The pattern of file URLs into this checkout, e.g. file:///home/runner/work/quena/quena/."""
    root = Path(__file__).resolve().parents[2].as_posix()  # C:/... on Windows, /... elsewhere
    if not root.startswith("/"):
        root = "/" + root
    # Windows paths are case-insensitive, and cargo may write the drive letter in either case.
    return re.compile(re.escape("file://" + root + "/"), re.IGNORECASE), root


def relativize(value, pattern):
    if isinstance(value, str):
        return pattern.sub("file:", value)
    if isinstance(value, list):
        return [relativize(v, pattern) for v in value]
    if isinstance(value, dict):
        return {k: relativize(v, pattern) for k, v in value.items()}
    return value


def tool_entries(bom):
    """metadata.tools in the 1.5 form (components), also from the legacy list form."""
    tools = bom["metadata"].get("tools")
    if isinstance(tools, dict):
        return [dict(t) for t in tools.get("components", [])]
    entries = []
    for t in tools or []:
        e = {"type": "application", "name": t.get("name", "")}
        if t.get("vendor"):
            e["publisher"] = t["vendor"]
        if t.get("version"):
            e["version"] = t["version"]
        entries.append(e)
    return entries


def timestamp():
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    when = (datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc) if epoch
            else datetime.datetime.now(datetime.timezone.utc))
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--platform", required=True)
    ap.add_argument("--description")
    ap.add_argument("--plugin", action="append", default=[], help="SBOM of a bundled plugin")
    ap.add_argument("parts", nargs="+", help="SBOMs of the program's parts")
    args = ap.parse_args()

    pattern, root = checkout_prefix()
    product_ref = f"pkg:github/hkiam/quena@{args.version}#{args.name}"
    components = {}
    dependencies = {}
    tools = {}
    roots = []
    triples = []

    for path, plugin in [(p, False) for p in args.parts] + [(p, True) for p in args.plugin]:
        bom = relativize(load(path), pattern)
        main_component = dict(bom["metadata"]["component"])
        ref = main_component.get("bom-ref")
        if not ref:
            fail(f"{path}: the main component has no bom-ref")
        if plugin:
            main_component["type"] = "library"
            props = [p for p in main_component.get("properties", []) if p.get("name") != "quena:plugin"]
            main_component["properties"] = props + [{"name": "quena:plugin", "value": main_component.get("name", "")}]
            # Not pkg:cargo/<name>: scanners would take the plugin for the crates.io crate of
            # that name (jwt, graphql …) and report its advisories.
            main_component["purl"] = f"pkg:github/hkiam/quena@v{args.version}#plugins/{main_component.get('name', '')}"
            main_component["components"] = [{k: v for k, v in c.items() if k != "purl"}
                                            for c in main_component.get("components", [])]
            if not main_component["components"]:
                del main_component["components"]
        if ref not in roots:
            roots.append(ref)
        for c in [main_component] + bom.get("components", []):
            components.setdefault(c.get("bom-ref") or json.dumps(c, sort_keys=True), c)
        for d in bom.get("dependencies", []):
            dependencies.setdefault(d["ref"], set()).update(d.get("dependsOn", []))
        for p in bom["metadata"].get("properties", []):
            if p.get("name") == "cdx:rustc:sbom:target:triple" and not plugin and p.get("value") not in triples:
                triples.append(p["value"])
        for t in tool_entries(bom):
            tools.setdefault((t.get("group"), t.get("name"), t.get("version")), t)

    dependencies[product_ref] = set(roots)
    known = set(components) | {product_ref}
    missing = sorted({r for ref, deps in dependencies.items() for r in deps | {ref}} - known)
    if missing:
        fail("dependencies on unknown components: " + ", ".join(missing[:5]))
    leftover = [c.get("bom-ref") for c in components.values() if root in json.dumps(c)]
    if leftover:
        fail(f"absolute checkout paths left in: {', '.join(map(str, leftover[:5]))}")

    product = {
        "type": "application",
        "bom-ref": product_ref,
        "name": args.name,
        "version": args.version,
        "licenses": [{"expression": "Apache-2.0"}],
        "purl": f"pkg:github/hkiam/quena@v{args.version}",
        "externalReferences": [{"type": "vcs", "url": REPOSITORY}],
    }
    if args.description:
        product["description"] = args.description

    def order(c):
        return (c.get("group", ""), c.get("name", ""), c.get("version", ""), c.get("bom-ref", ""))

    out = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp(),
            "tools": {"components": sorted(tools.values(), key=order)},
            "component": product,
            "properties": [{"name": "quena:platform", "value": args.platform}]
            + [{"name": "cdx:rustc:sbom:target:triple", "value": t} for t in triples],
        },
        "components": sorted(components.values(), key=order),
        "dependencies": [{"ref": ref, "dependsOn": sorted(deps)} for ref, deps in sorted(dependencies.items())],
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
