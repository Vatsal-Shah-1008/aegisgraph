import socket
import re
from typing import Dict, Any

class WhoisService:
    @staticmethod
    def _query_whois_socket(domain: str, server: str = "whois.iana.org", port: int = 43) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((server, port))
            s.send((domain + "\r\n").encode("utf-8"))
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            return response.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @classmethod
    def lookup(cls, domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()
        results: Dict[str, Any] = {
            "domain": domain,
            "registrar": "Unknown",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "name_servers": [],
            "raw_text": "",
            "graph_nodes": [],
            "graph_edges": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Querying WHOIS directory for {domain}...")

        # Step 1: Query IANA to find the authoritative TLD WHOIS server
        iana_res = cls._query_whois_socket(domain, "whois.iana.org")
        refer_match = re.search(r"refer:\s+([^\s]+)", iana_res, re.IGNORECASE)
        tld_server = refer_match.group(1) if refer_match else "whois.verisign-grs.com"

        # Step 2: Query authoritative server
        whois_data = cls._query_whois_socket(domain, tld_server)
        if not whois_data:
            # Fallback to general servers
            whois_data = cls._query_whois_socket(domain, "whois.internic.net")

        results["raw_text"] = whois_data[:2000] if whois_data else "No whois response received."

        # Parse Fields
        reg_match = re.search(r"(?:Registrar|registrar name):\s*(.+)", whois_data, re.IGNORECASE)
        if reg_match:
            results["registrar"] = reg_match.group(1).strip()
            results["logs"].append(f"[+] Registrar: {results['registrar']}")

        created_match = re.search(r"(?:Creation Date|Created|registered on):\s*(.+)", whois_data, re.IGNORECASE)
        if created_match:
            results["creation_date"] = created_match.group(1).strip()
            results["logs"].append(f"[+] Created Date: {results['creation_date']}")

        exp_match = re.search(r"(?:Registry Expiry Date|Expir\w+ Date):\s*(.+)", whois_data, re.IGNORECASE)
        if exp_match:
            results["expiration_date"] = exp_match.group(1).strip()
            results["logs"].append(f"[+] Expiry Date: {results['expiration_date']}")

        ns_matches = re.findall(r"Name Server:\s*([^\s]+)", whois_data, re.IGNORECASE)
        for ns in set(ns_matches):
            results["name_servers"].append(ns.lower())
            results["logs"].append(f"    └─ NS: {ns.lower()}")

        # Graph Entities
        root_node_id = f"domain_{domain}"
        if results["registrar"] != "Unknown":
            reg_node_id = f"registrar_{results['registrar'].replace(' ', '_')}"
            results["graph_nodes"].append({
                "id": reg_node_id,
                "label": f"Registrar: {results['registrar'][:20]}",
                "type": "registrar",
                "risk": "info"
            })
            results["graph_edges"].append({
                "source": root_node_id,
                "target": reg_node_id,
                "label": "REGISTERED_WITH"
            })

        results["logs"].append(f"[SUCCESS] WHOIS extraction completed.")
        return results
