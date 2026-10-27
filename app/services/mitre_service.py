from typing import Dict, Any, List

# Standard MITRE ATT&CK Enterprise Matrix mapping for External Attack Surface Reconnaissance
MITRE_TACTICS_MAPPING = {
    "FINDING-TAKEOVER-01": {
        "tactic": "TA0001 - Initial Access",
        "technique_id": "T1584.004",
        "technique_name": "Compromise Infrastructure: DNS Server / Dangling DNS",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "cvss_base_score": 9.3,
        "cwe_id": "CWE-284: Improper Access Control"
    },
    "FINDING-EXPOSURE": {
        "tactic": "TA0001 - Initial Access / TA0007 - Discovery",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_base_score": 9.8,
        "cwe_id": "CWE-200: Exposure of Sensitive Information to Unauthorized Actor"
    },
    "FINDING-SSL-EXPIRED": {
        "tactic": "TA0006 - Credential Access / TA0040 - Impact",
        "technique_id": "T1557",
        "technique_name": "Adversary-in-the-Middle (MitM)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cvss_base_score": 7.4,
        "cwe_id": "CWE-295: Improper Certificate Validation"
    },
    "FINDING-HEADERS-WEAK": {
        "tactic": "TA0005 - Defense Evasion",
        "technique_id": "T1562.001",
        "technique_name": "Impair Defenses: Disable or Weaken Defensive Headers",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cvss_base_score": 5.4,
        "cwe_id": "CWE-693: Protection Mechanism Failure"
    },
    "FINDING-EMAIL-SPOOF": {
        "tactic": "TA0001 - Initial Access",
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link / Domain Spoofing",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "cvss_base_score": 6.5,
        "cwe_id": "CWE-345: Insufficient Verification of Data Authenticity"
    }
}

class MitreAttackService:
    @staticmethod
    def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for finding in findings:
            fid = finding.get("id", "")
            mapping = None
            if "TAKEOVER" in fid:
                mapping = MITRE_TACTICS_MAPPING.get("FINDING-TAKEOVER-01")
            elif "EXPOSURE" in fid:
                mapping = MITRE_TACTICS_MAPPING.get("FINDING-EXPOSURE")
            elif "SSL-EXPIRED" in fid:
                mapping = MITRE_TACTICS_MAPPING.get("FINDING-SSL-EXPIRED")
            elif "HEADERS" in fid:
                mapping = MITRE_TACTICS_MAPPING.get("FINDING-HEADERS-WEAK")
            else:
                mapping = MITRE_TACTICS_MAPPING.get("FINDING-EMAIL-SPOOF")

            if mapping:
                finding["mitre_tactic"] = mapping["tactic"]
                finding["mitre_technique_id"] = mapping["technique_id"]
                finding["mitre_technique_name"] = mapping["technique_name"]
                finding["cvss_vector"] = mapping["cvss_vector"]
                finding["cvss_score"] = mapping["cvss_base_score"]
                finding["cwe_id"] = mapping["cwe_id"]
            enriched.append(finding)
        return enriched
