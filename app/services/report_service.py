from datetime import datetime
from typing import Dict, Any, List

class ReportService:
    @staticmethod
    def generate_audit_dossier(
        domain: str,
        correlation_data: Dict[str, Any],
        graph_data: Dict[str, Any],
        topology_data: Dict[str, Any]
    ) -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        findings = correlation_data.get("findings", [])
        risk_score = correlation_data.get("overall_risk_score", 0)
        risk_level = correlation_data.get("risk_level", "UNKNOWN")

        report = f"""# AEGISGRAPH: AUTONOMOUS ATTACK SURFACE AUDIT DOSSIER
**Project Title:** Autonomous Attack Surface Intelligence & Threat Graph Analysis Engine  
**Author:** Vatsal Shah (Final Year Capstone Project)  
**Target Organization / Scope:** `{domain}`  
**Audit Timestamp:** {timestamp}  
**Classification:** Confidential Security Evaluation  

---

## 1. Executive Summary & Threat Score
AegisGraph conducted an automated, multi-modal reconnaissance sweep against `{domain}`. Utilizing passive DNS harvesting, cryptographic certificate evaluation, network perimeter probers, and topological graph analysis, the platform mapped the public-facing footprint.

* **Composite External Risk Score:** **{risk_score}/100** (`{risk_level}`)
* **Total Discovered Graph Entities:** {len(graph_data.get('nodes', []))} Assets
* **Total Chained Compromise Paths:** {len(topology_data.get('transitive_attack_paths', []))} Attack Vectors

---

## 2. MITRE ATT&CK® Enterprise Alignment & CVSS v3.1 Scoring

| Finding ID | Severity | CVSS v3.1 | MITRE ATT&CK Technique | CWE |
| :--- | :--- | :--- | :--- | :--- |
"""
        for f in findings:
            report += f"| `{f.get('id', 'N/A')}` | **{f.get('severity', 'MED')}** | `{f.get('cvss_score', 7.0)}` | {f.get('mitre_technique_id', 'T1596')} - {f.get('mitre_technique_name', 'Recon')} | `{f.get('cwe_id', 'CWE-200')}` |\n"

        report += f"""
---

## 3. Graph Topological Centrality ("Crown Jewels")
Based on degree centrality algorithms, the following infrastructure nodes exhibit the highest interconnectedness, making them critical single points of failure:

"""
        for c in topology_data.get("centrality_analysis", []):
            report += f"* **`{c['label']}`** (Type: `{c['type']}`): Centrality Coefficient **{c['centrality_score']}** with {c['connections']} direct graph linkages.\n"

        report += f"""
---

## 4. Multi-Hop Transitive Attack Paths
The AI correlator identified transitive compromise routes linking unmonitored perimeter assets to core services:

"""
        for ap in topology_data.get("transitive_attack_paths", []):
            report += f"### ⚠️ Path: {ap['entry_point']} -> {ap['target_asset']}\n"
            report += f"* **Risk Level:** `{ap['risk_level']}` ({ap['hops']} Network Hops)\n"
            report += f"* **Vector Chain:** `{ap['path_chain']}`\n\n"

        report += f"""
---

## 5. Automated Infrastructure-as-Code (IaC) Remediation
To neutralize the identified vulnerabilities, the following configurations should be applied immediately:

"""
        for f in findings:
            if f.get("remediation"):
                report += f"#### Mitigation for {f['title']}:\n```bash\n{f['remediation']}\n```\n\n"

        report += """
---
*Generated autonomously by AegisGraph Platform - Developed by Vatsal Shah*
"""
        return report
