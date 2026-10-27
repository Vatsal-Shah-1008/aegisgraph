import dns.resolver
import dns.reversename
import socket
from typing import Dict, Any, List

KNOWN_TAKEOVER_PATTERNS = {
    "s3.amazonaws.com": "AWS S3 Bucket",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku App",
    "azurewebsites.net": "Azure Cloud App",
    "zendesk.com": "Zendesk Help Center",
    "ghost.io": "Ghost Blog",
    "pantheonsite.io": "Pantheon Hosting",
    "wordpress.com": "WordPress",
    "unbouncepages.com": "Unbounce Landing Page",
}

class DNSService:
    @staticmethod
    def resolve_domain(domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()
        results: Dict[str, Any] = {
            "domain": domain,
            "records": {},
            "reverse_ptr": [],
            "dangling_checks": [],
            "graph_nodes": [],
            "graph_edges": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Commencing DNS resolution for target: {domain}")

        # Root Domain Node
        root_node_id = f"domain_{domain}"
        results["graph_nodes"].append({
            "id": root_node_id,
            "label": domain,
            "type": "domain",
            "risk": "info"
        })

        # Use fast, reliable public resolvers with fallback
        resolver = dns.resolver.Resolver(configure=True)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        resolver.timeout = 2.0
        resolver.lifetime = 2.5

        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

        for r_type in record_types:
            try:
                answers = resolver.resolve(domain, r_type)
                records = [str(r.to_text()).strip('"') for r in answers]
                results["records"][r_type] = records
                results["logs"].append(f"[+] Found {len(records)} record(s) for type {r_type}: {', '.join(records[:3])}{'...' if len(records) > 3 else ''}")

                # Process records for graph
                if r_type == "A":
                    for ip in records:
                        ip_node_id = f"ip_{ip}"
                        results["graph_nodes"].append({
                            "id": ip_node_id,
                            "label": ip,
                            "type": "ip",
                            "risk": "info"
                        })
                        results["graph_edges"].append({
                            "source": root_node_id,
                            "target": ip_node_id,
                            "label": "RESOLVES_TO"
                        })
                        # PTR Reverse lookup
                        try:
                            rev_name = dns.reversename.from_address(ip)
                            ptr_ans = resolver.resolve(rev_name, "PTR")
                            for p in ptr_ans:
                                ptr_str = str(p).rstrip('.')
                                results["reverse_ptr"].append({"ip": ip, "hostname": ptr_str})
                                results["logs"].append(f"    └─ Reverse PTR for {ip} -> {ptr_str}")
                        except Exception:
                            pass

                elif r_type == "CNAME":
                    for target in records:
                        target_clean = target.rstrip(".")
                        cname_node_id = f"cname_{target_clean}"
                        
                        # Check for dangling takeover signature
                        is_dangling = False
                        matched_service = "Unknown Cloud Asset"
                        for pattern, svc in KNOWN_TAKEOVER_PATTERNS.items():
                            if pattern in target_clean.lower():
                                is_dangling = True
                                matched_service = svc
                                break

                        results["graph_nodes"].append({
                            "id": cname_node_id,
                            "label": target_clean,
                            "type": "cloud_bucket" if is_dangling else "cname",
                            "risk": "critical" if is_dangling else "info"
                        })
                        results["graph_edges"].append({
                            "source": root_node_id,
                            "target": cname_node_id,
                            "label": "ALIASES_TO",
                            "threat": is_dangling
                        })

                        if is_dangling:
                            results["dangling_checks"].append({
                                "cname": target_clean,
                                "service": matched_service,
                                "status": "POTENTIAL_TAKEOVER_EXPOSURE",
                                "severity": "HIGH",
                                "detail": f"Subdomain points to external service '{matched_service}'. Verify ownership to prevent subdomain takeover."
                            })
                            results["logs"].append(f"[!] WARNING: Potential dangling CNAME to {matched_service} ({target_clean})")

                elif r_type in ["MX", "NS"]:
                    for item in records:
                        item_clean = item.split()[-1].rstrip(".") if r_type == "MX" else item.rstrip(".")
                        item_id = f"{r_type.lower()}_{item_clean}"
                        results["graph_nodes"].append({
                            "id": item_id,
                            "label": item_clean,
                            "type": "mail_server" if r_type == "MX" else "nameserver",
                            "risk": "info"
                        })
                        results["graph_edges"].append({
                            "source": root_node_id,
                            "target": item_id,
                            "label": "HANDLED_BY" if r_type == "MX" else "DELEGATED_TO"
                        })

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                # Fallback to standard socket if DNS timed out
                if r_type == "A" and "ip" not in [n["type"] for n in results["graph_nodes"]]:
                    try:
                        ip = socket.gethostbyname(domain)
                        ip_node_id = f"ip_{ip}"
                        results["records"]["A"] = [ip]
                        results["graph_nodes"].append({
                            "id": ip_node_id,
                            "label": ip,
                            "type": "ip",
                            "risk": "info"
                        })
                        results["graph_edges"].append({
                            "source": root_node_id,
                            "target": ip_node_id,
                            "label": "RESOLVES_TO"
                        })
                        results["logs"].append(f"[+] Fallback IP resolved: {ip}")
                    except Exception:
                        results["logs"].append(f"[-] Query for {r_type} failed: {str(e)}")
                else:
                    results["logs"].append(f"[-] Query for {r_type} timed out.")

        results["logs"].append(f"[SUCCESS] DNS mapping complete. Generated {len(results['graph_nodes'])} graph entities.")
        return results
