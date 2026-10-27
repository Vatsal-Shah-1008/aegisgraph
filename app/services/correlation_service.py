from typing import Dict, Any, List

class CorrelationService:
    @staticmethod
    def correlate_findings(
        domain: str,
        dns_data: Dict[str, Any] = None,
        ssl_data: Dict[str, Any] = None,
        port_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        score_penalty = 0

        # 1. Evaluate Dangling CNAME & Cloud Takeovers
        if dns_data and dns_data.get("dangling_checks"):
            for dangling in dns_data["dangling_checks"]:
                score_penalty += 25
                findings.append({
                    "id": "FINDING-TAKEOVER-01",
                    "title": f"Dangling DNS Record to {dangling['service']}",
                    "severity": "CRITICAL",
                    "cve": "CWE-284 (Improper Access Control)",
                    "summary": f"Subdomain {domain} points to an external cloud resource ({dangling['cname']}). If this resource was deleted or unclaimed, an adversary can claim it to achieve full subdomain takeover.",
                    "attack_path": f"{domain} -> CNAME {dangling['cname']} -> Unallocated Cloud Bucket -> Subdomain Takeover & Cookie Theft",
                    "remediation": f"""# Fix: Remove or update the orphaned DNS record
# AWS CLI or Terraform:
terraform {{
  # Delete or update Route53 record
  resource "aws_route53_record" "subdomain_fix" {{
    zone_id = "ZXXXXXXXXXXX"
    name    = "{domain}"
    type    = "CNAME"
    ttl     = 300
    records = ["target-production-asset.internal"]
  }}
}}"""
                })

        # 2. Evaluate Exposed Risky Ports
        if port_data and port_data.get("open_ports"):
            for port in port_data["open_ports"]:
                if port.get("is_risky"):
                    score_penalty += 20
                    findings.append({
                        "id": f"FINDING-EXPOSURE-{port['port']}",
                        "title": f"Exposed Dangerous Port: {port['port']}/{port['service']}",
                        "severity": "HIGH",
                        "cve": "CWE-200 (Information Exposure)",
                        "summary": f"Port {port['port']} running {port['service']} is exposed to the public internet. Database and administration ports should never be reachable externally.",
                        "attack_path": f"Public Internet -> Port {port['port']} -> Direct Authentication Brute Force / RCE Exploit",
                        "remediation": f"""# Fix: Restrict access via Firewall / Security Group (UFW or AWS SG)
sudo ufw deny from any to any port {port['port']} proto tcp
# Or allow only VPN / Bastion IP:
sudo ufw allow from 10.0.0.0/8 to any port {port['port']} proto tcp"""
                    })

        # 3. Evaluate SSL / TLS Status
        if ssl_data:
            ssl_info = ssl_data.get("ssl_info")
            if ssl_info and isinstance(ssl_info, dict):
                days_left = ssl_info.get("days_remaining", 999)
                if days_left < 0:
                    score_penalty += 30
                    findings.append({
                        "id": "FINDING-SSL-EXPIRED",
                        "title": "Expired SSL/TLS Certificate",
                        "severity": "CRITICAL",
                        "cve": "CWE-295 (Improper Certificate Validation)",
                        "summary": f"The TLS certificate for {domain} has expired ({abs(days_left)} days ago). Browsers will display security warnings, and data integrity is compromised.",
                        "attack_path": f"Client -> {domain} -> Certificate Validation Error -> Opportunistic MitM Interception",
                        "remediation": """# Fix: Renew Let's Encrypt / Certbot Certificate immediately:
sudo certbot renew --force-renewal
sudo systemctl reload nginx"""
                    })
                elif days_left < 15:
                    score_penalty += 10
                    findings.append({
                        "id": "FINDING-SSL-EXPIRING",
                        "title": f"SSL Certificate Expiring Soon ({days_left} days remaining)",
                        "severity": "MEDIUM",
                        "cve": "Operational Risk",
                        "summary": f"Certificate expires in {days_left} days. Ensure automated renewal cron is active.",
                        "attack_path": "Imminent certificate lapse -> Service downtime",
                        "remediation": "sudo certbot renew --dry-run"
                    })

            # Check Missing Security Headers
            missing_hdrs = ssl_data.get("missing_headers", [])
            hsts_missing = any(h["header"] == "Strict-Transport-Security" for h in missing_hdrs)
            csp_missing = any(h["header"] == "Content-Security-Policy" for h in missing_hdrs)

            if hsts_missing or csp_missing:
                score_penalty += 10
                missing_names = ", ".join([h["header"] for h in missing_hdrs[:3]])
                findings.append({
                    "id": "FINDING-HEADERS-WEAK",
                    "title": "Missing Defense-in-Depth HTTP Headers",
                    "severity": "MEDIUM",
                    "cve": "CWE-693 (Protection Mechanism Failure)",
                    "summary": f"Missing critical headers: {missing_names}. This leaves endpoints exposed to SSL stripping and clickjacking attacks.",
                    "attack_path": f"Attacker -> Unprotected HTTP Transport -> SSL Stripping / Clickjacking iframe exploit",
                    "remediation": """# Fix: Add headers in Nginx configuration:
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;"""
                })

        # Calculate final risk score (0 to 100)
        risk_score = min(100, max(12, score_penalty))

        return {
            "target": domain,
            "overall_risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 60 else ("HIGH" if risk_score >= 40 else ("MEDIUM" if risk_score >= 20 else "LOW")),
            "total_findings": len(findings),
            "findings": findings,
            "ai_copilot_verdict": CorrelationService._generate_verdict(domain, risk_score, findings)
        }

    @staticmethod
    def _generate_verdict(domain: str, score: int, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return f"Asset {domain} shows standard defensive hygiene. No high-severity multi-hop attack vectors detected in current external footprint."
        
        highest_severity = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH"
        return f"Autonomous analysis identified {len(findings)} correlation risks on {domain} (Severity: {highest_severity}). The most dangerous path involves {findings[0]['title']}. Immediate remediation is recommended to reduce exposure score from {score}/100."
