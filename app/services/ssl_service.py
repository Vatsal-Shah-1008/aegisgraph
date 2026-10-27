import socket
import ssl
import httpx
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse

class SSLService:
    @staticmethod
    def inspect_ssl_and_headers(target: str) -> Dict[str, Any]:
        target = target.strip().lower()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            hostname = parsed.hostname or target
        else:
            hostname = target.split("/")[0].split(":")[0]

        results: Dict[str, Any] = {
            "hostname": hostname,
            "ssl_info": None,
            "san_subdomains": [],
            "security_headers": {},
            "server_banner": None,
            "missing_headers": [],
            "graph_nodes": [],
            "graph_edges": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying SSL/TLS Certificate and Security Headers for {hostname}...")

        # 1. SSL/TLS Certificate Extraction
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, 443), timeout=4.0) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # If cert is empty because CERT_NONE, fetch DER and parse
                    if not cert:
                        der_cert = ssock.getpeercert(binary_form=True)
                        import cryptography.x509 as x509
                        from cryptography.hazmat.backends import default_backend
                        crypto_cert = x509.load_der_x509_certificate(der_cert, default_backend())

                        issuer_str = crypto_cert.issuer.rfc4514_string()
                        subject_str = crypto_cert.subject.rfc4514_string()
                        not_before = crypto_cert.not_valid_before_utc.isoformat()
                        not_after = crypto_cert.not_valid_after_utc.isoformat()
                        days_left = (crypto_cert.not_valid_after_utc - datetime.now(crypto_cert.not_valid_after_utc.tzinfo)).days

                        # Extract SANs
                        sans = []
                        try:
                            ext = crypto_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            sans = ext.value.get_values_for_type(x509.DNSName)
                        except Exception:
                            pass

                        results["ssl_info"] = {
                            "issuer": issuer_str,
                            "subject": subject_str,
                            "valid_from": not_before,
                            "valid_until": not_after,
                            "days_remaining": days_left,
                            "expired": days_left < 0
                        }
                        results["san_subdomains"] = sans
                    else:
                        results["ssl_info"] = cert
                    
                    results["logs"].append(f"[+] SSL Handshake established on port 443 (TLS {ssock.version()})")
                    if results["ssl_info"]:
                        results["logs"].append(f"    └─ Issuer: {results['ssl_info'].get('issuer', 'Unknown')}")
                        results["logs"].append(f"    └─ Validity: {results['ssl_info'].get('days_remaining', 'N/A')} days remaining")
                    
                    if results["san_subdomains"]:
                        results["logs"].append(f"[+] Harvested {len(results['san_subdomains'])} Subdomains/SANs from Certificate:")
                        for san in results["san_subdomains"][:6]:
                            results["logs"].append(f"    • {san}")
                        if len(results["san_subdomains"]) > 6:
                            results["logs"].append(f"    • ... and {len(results['san_subdomains']) - 6} more")

                    # Add SSL Cert Node to Graph
                    cert_node_id = f"cert_{hostname}"
                    results["graph_nodes"].append({
                        "id": cert_node_id,
                        "label": f"SSL Cert ({ssock.version()})",
                        "type": "ssl_cert",
                        "risk": "critical" if results["ssl_info"].get("expired") else "info"
                    })
                    results["graph_edges"].append({
                        "source": f"domain_{hostname}",
                        "target": cert_node_id,
                        "label": "SECURED_BY"
                    })

                    # Add SAN subdomains to Graph
                    for san in results["san_subdomains"][:10]:
                        if san != hostname and not san.startswith("*"):
                            san_id = f"san_{san}"
                            results["graph_nodes"].append({
                                "id": san_id,
                                "label": san,
                                "type": "subdomain",
                                "risk": "info"
                            })
                            results["graph_edges"].append({
                                "source": cert_node_id,
                                "target": san_id,
                                "label": "SHARED_CERT_SAN"
                            })

        except Exception as e:
            results["logs"].append(f"[-] SSL Inspection failed on port 443: {str(e)}")

        # 2. HTTP Security Headers Inspection
        try:
            with httpx.Client(timeout=4.0, verify=False, follow_redirects=True) as client:
                resp = client.get(f"https://{hostname}")
                headers = dict(resp.headers)
                results["server_banner"] = headers.get("server")

                critical_headers = [
                    ("Strict-Transport-Security", "Enforces HTTPS connections and prevents SSL stripping"),
                    ("Content-Security-Policy", "Protects against Cross-Site Scripting (XSS) and data injection"),
                    ("X-Frame-Options", "Mitigates Clickjacking attacks"),
                    ("X-Content-Type-Options", "Prevents MIME-sniffing exploits"),
                    ("Referrer-Policy", "Controls referrer privacy leaks")
                ]

                results["logs"].append(f"[+] HTTP Status: {resp.status_code}")
                if results["server_banner"]:
                    results["logs"].append(f"[!] Server Header Exposed: {results['server_banner']}")

                for hdr, desc in critical_headers:
                    val = headers.get(hdr.lower())
                    if val:
                        results["security_headers"][hdr] = val
                        results["logs"].append(f"    [OK] {hdr}: {val[:45]}{'...' if len(val) > 45 else ''}")
                    else:
                        results["missing_headers"].append({"header": hdr, "description": desc})
                        results["logs"].append(f"    [WARN] Missing Header: {hdr}")

        except Exception as e:
            results["logs"].append(f"[-] HTTP Header audit failed: {str(e)}")

        return results
