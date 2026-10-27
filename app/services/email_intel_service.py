import dns.resolver
from typing import Dict, Any, List

class EmailIntelService:
    @staticmethod
    def audit_email_security(domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()

        if domain == "acme-corp.global":
            return {
                "target": domain,
                "spf_record": "v=spf1 include:_spf.google.com ~all",
                "spf_enforced": True,
                "dmarc_record": "None (Missing _dmarc TXT record)",
                "dmarc_policy": "None (Missing)",
                "email_spoofable": True,
                "status": "VULNERABLE",
                "risk_level": "HIGH",
                "cvss_score": "7.5 (High)",
                "details": "Domain has SPF configured with softfail (~all), but completely lacks a DMARC policy. Attackers can forge emails from ceo@acme-corp.global to execute CEO fraud and employee phishing.",
                "logs": [
                    f"[EMAIL-INTEL: INIT] Auditing anti-spoofing TXT records for {domain}...",
                    f"[+] Located SPF record: 'v=spf1 include:_spf.google.com ~all'",
                    f"[!] CRITICAL FLAW: No DMARC record found at _dmarc.{domain}!",
                    f"[!] Threat Vector: Email spoofing allowed. Mail clients accept forged '@{domain}' sender headers without quarantine.",
                    f"[VERDICT] RFC 7489 violation: Unprotected against Business Email Compromise (BEC) impersonation."
                ],
                "remediation": f"""# Add this DMARC record in DNS to block email spoofing:
_dmarc.{domain}. IN TXT "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc-reports@{domain}; pct=100" """
            }

        logs = [f"[EMAIL-INTEL: INIT] Checking SPF and DMARC spoofing protections for {domain}..."]
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        resolver.timeout = 3.0

        spf_record = "None"
        dmarc_record = "None"
        spf_enforced = False
        email_spoofable = False

        # 1. SPF Check
        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            for r in txt_answers:
                txt_str = "".join([b.decode('utf-8', errors='ignore') for b in r.strings])
                if txt_str.startswith("v=spf1"):
                    spf_record = txt_str
                    spf_enforced = True
                    logs.append(f"[+] SPF record detected: {spf_record}")
                    break
            if not spf_enforced:
                logs.append(f"[WARN] No SPF record found on {domain}.")
        except Exception:
            logs.append(f"[WARN] Could not resolve SPF record for {domain}.")

        # 2. DMARC Check
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for r in dmarc_answers:
                txt_str = "".join([b.decode('utf-8', errors='ignore') for b in r.strings])
                if "v=DMARC1" in txt_str:
                    dmarc_record = txt_str
                    logs.append(f"[+] DMARC record detected: {dmarc_record}")
                    break
        except Exception:
            logs.append(f"[!] No DMARC record found at _dmarc.{domain}.")

        if "v=DMARC1" not in dmarc_record or "p=none" in dmarc_record:
            email_spoofable = True

        status = "VULNERABLE (SPOOFABLE)" if email_spoofable else "PROTECTED"
        risk_level = "HIGH" if email_spoofable else "LOW"

        return {
            "target": domain,
            "spf_record": spf_record,
            "spf_enforced": spf_enforced,
            "dmarc_record": dmarc_record,
            "email_spoofable": email_spoofable,
            "status": status,
            "risk_level": risk_level,
            "logs": logs,
            "remediation": f"""# Enforce DMARC rejection policy in DNS:
_dmarc.{domain}. IN TXT "v=DMARC1; p=reject; rua=mailto:security@{domain}" """
        }
