"""Export formats for JWT Sentinel: SARIF (IDE/CI) and JUnit (test framework)."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from jwtsentinel.analyzer import Analysis


def to_sarif(analysis: Analysis, token_fingerprint: str) -> str:
    """Convert an Analysis to SARIF format (suitable for CI/IDE consumption)."""
    findings = analysis.findings
    tool = {"driver": {"name": "JWT Sentinel", "version": "1.1.0",
                       "informationUri": "https://github.com/nikhilsankhla/jwtsentinel"}}
    
    results = []
    for finding in findings:
        results.append({
            "ruleId": finding.code,
            "ruleIndex": len(results),
            "message": {"text": finding.title + " - " + finding.detail},
            "level": {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "none"}.get(finding.severity, "none"),
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "token"}}}],
            "properties": {"severity": finding.severity, "fix": finding.fix,
                           "references": finding.references},
        })
    
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/schema/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": tool,
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeInUtc": datetime.now(timezone.utc).isoformat(),
            }],
        }],
    }
    return json.dumps(sarif, indent=2)


def to_junit(analysis: Analysis) -> str:
    """Convert an Analysis to JUnit XML format (suitable for CI test reports)."""
    import xml.etree.ElementTree as ET
    
    root = ET.Element("testsuite")
    root.set("name", "jwtsentinel")
    root.set("tests", str(len(analysis.findings) + 1))
    root.set("failures", str(sum(1 for f in analysis.findings if f.severity in ("critical", "high"))))
    root.set("errors", "0")
    root.set("time", "0.0")
    
    test_case = ET.SubElement(root, "testcase")
    test_case.set("name", "analyze")
    test_case.set("classname", "jwtsentinel.Analysis")
    test_case.set("time", f"{analysis.risk_score}")
    
    for finding in analysis.findings:
        severity = finding.severity.upper()
        if severity in ("CRITICAL", "HIGH"):
            failure = ET.SubElement(test_case, "failure")
            failure.set("message", f"{finding.code}: {finding.title}")
            failure.text = f"Detail: {finding.detail}\nFix: {finding.fix}"
        else:
            warning = ET.SubElement(test_case, "warning")
            warning.text = f"{finding.severity}: {finding.title}"
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    return ET.tostring(root, encoding="unicode")