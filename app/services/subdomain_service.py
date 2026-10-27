import asyncio
import socket
from typing import Dict, Any, List

TOP_SUBDOMAINS = [
    "api", "dev", "stage", "staging", "auth", "vpn", "admin", "portal",
    "mail", "webmail", "corp", "internal", "jenkins", "gitlab", "grafana",
    "k8s", "beta", "docs", "app", "cloud", "vault", "monitor", "remote",
    "gateway", "test", "demo", "status", "secure", "billing", "dashboard"
]

class SubdomainService:
    @staticmethod
    async def probe_subdomain(sub: str, base_domain: str) -> Dict[str, Any]:
        fqdn = f"{sub}.{base_domain}"
        loop = asyncio.get_running_loop()
        try:
            # Non-blocking DNS resolve
            addrinfo = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            return {
                "subdomain": fqdn,
                "prefix": sub,
                "ip": addrinfo,
                "alive": True
            }
        except Exception:
            return {"subdomain": fqdn, "prefix": sub, "ip": None, "alive": False}

    @classmethod
    async def enumerate_subdomains(cls, base_domain: str) -> Dict[str, Any]:
        base_domain = base_domain.strip().lower()
        results: Dict[str, Any] = {
            "domain": base_domain,
            "discovered_subdomains": [],
            "total_probed": len(TOP_SUBDOMAINS),
            "graph_nodes": [],
            "graph_edges": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Launching high-speed async discovery on {len(TOP_SUBDOMAINS)} target prefixes for {base_domain}...")

        tasks = [cls.probe_subdomain(sub, base_domain) for sub in TOP_SUBDOMAINS]
        probe_results = await asyncio.gather(*tasks)

        root_node_id = f"domain_{base_domain}"

        for res in probe_results:
            if res["alive"]:
                results["discovered_subdomains"].append(res)
                results["logs"].append(f"[+] DISCOVERED: {res['subdomain']} -> {res['ip']}")

                # Graph Nodes & Edges
                sub_node_id = f"sub_{res['subdomain']}"
                ip_node_id = f"ip_{res['ip']}"

                # Is it a high-risk prefix? (e.g. dev, admin, vpn, jenkins)
                is_sensitive = res["prefix"] in ["dev", "stage", "admin", "jenkins", "vpn", "vault"]

                results["graph_nodes"].append({
                    "id": sub_node_id,
                    "label": res["subdomain"],
                    "type": "subdomain",
                    "risk": "warning" if is_sensitive else "info"
                })
                results["graph_edges"].append({
                    "source": root_node_id,
                    "target": sub_node_id,
                    "label": "SUBDOMAIN_OF"
                })

                results["graph_nodes"].append({
                    "id": ip_node_id,
                    "label": res["ip"],
                    "type": "ip",
                    "risk": "info"
                })
                results["graph_edges"].append({
                    "source": sub_node_id,
                    "target": ip_node_id,
                    "label": "RESOLVES_TO"
                })

        results["logs"].append(f"[SUCCESS] Subdomain enumeration complete. Identified {len(results['discovered_subdomains'])} live endpoints.")
        return results
