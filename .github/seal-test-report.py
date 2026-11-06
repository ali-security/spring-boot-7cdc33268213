"""Sealed-build test report: totals per module, each skipped test with its reason
(read from the JUnit XML or, when absent, from the test source), and per-class
counts for the classes covering the CVE-patched source paths."""
import glob
import os
import re
import sys
import xml.etree.ElementTree as ET

WATCH = ("ApplicationTempTests", "EndpointRequestTests")


def source_reason(sources, cls, method):
    simple = cls.split(".")[-1].split("$")[-1]
    ordered = sorted(sources.items(), key=lambda kv: os.path.basename(kv[0]) != simple + ".java")
    for path, text in ordered:
        m = re.search(r"\n([ \t]*@[^\n]*\n)*[ \t]*(?:public |protected )?void " + re.escape(method) + r"\(", text)
        if not m:
            continue
        annotations = [a.strip() for a in re.findall(r"@[^\n]*", m.group(0)) if not a.strip().startswith("@Test")]
        body = text[m.end():m.end() + 2500].split("\n\t}", 1)[0]
        assumes = [line.strip() for line in body.splitlines() if "assume" in line.lower()]
        found = annotations + assumes
        if found:
            return "; ".join(found) + " [" + os.path.basename(path) + "]"
    for path, text in sources.items():
        if os.path.basename(path) == simple + ".java":
            head = text.split("class " + simple, 1)[0]
            cls_ann = [a.strip() for a in re.findall(r"\n(@(?:Disabled|Enabled)[^\n]*)", head)]
            if cls_ann:
                return "; ".join(cls_ann) + " [class-level, " + os.path.basename(path) + "]"
    return "no reason found in source"


def main():
    grand = [0, 0, 0, 0]
    for mod in sys.argv[1:]:
        sources = {}
        for p in glob.glob(os.path.join(mod, "src", "test", "**", "*.java"), recursive=True):
            with open(p, encoding="utf-8") as fh:
                sources[p] = fh.read()
        totals = [0, 0, 0, 0]
        watched = {}
        for x in sorted(glob.glob(os.path.join(mod, "build", "test-results", "test", "*.xml"))):
            for tc in ET.parse(x).getroot().iter("testcase"):
                cls = tc.get("classname")
                name = tc.get("name")
                totals[0] += 1
                status = "passed"
                if tc.find("failure") is not None or tc.find("error") is not None:
                    totals[2] += 1
                    status = "failed"
                elif tc.find("skipped") is not None:
                    totals[3] += 1
                    status = "skipped"
                    method = re.sub(r"\(.*", "", name).strip()
                    reason = tc.find("skipped").get("message") or source_reason(sources, cls, method)
                    print(f"SKIPPED TEST: {cls}#{name} ({mod}) -- reason: {reason}")
                else:
                    totals[1] += 1
                simple = cls.split(".")[-1]
                if simple in WATCH:
                    w = watched.setdefault(cls, [0, 0, 0, 0])
                    w[0] += 1
                    w[{"passed": 1, "failed": 2, "skipped": 3}[status]] += 1
        print(f"SEAL TEST RESULTS {mod}: tests: {totals[0]}, passed: {totals[1]}, failed: {totals[2]}, skipped: {totals[3]}")
        for cls, w in sorted(watched.items()):
            print(f"PATCHED-PATH tests: {cls}: tests: {w[0]}, passed: {w[1]}, failed: {w[2]}, skipped: {w[3]}")
        grand = [a + b for a, b in zip(grand, totals)]
    print(f"SEAL TEST RESULTS TOTAL: tests: {grand[0]}, passed: {grand[1]}, failed: {grand[2]}, skipped: {grand[3]}")


if __name__ == "__main__":
    main()
