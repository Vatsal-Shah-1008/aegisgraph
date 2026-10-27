import socket
import asyncio
from typing import Dict, Any, List

COMMON_PORTS = [
    (21, "FTP", "Cleartext file transfer service"),
    (22, "SSH", "Remote secure shell access"),
    (25, "SMTP", "Mail transfer service"),
    (53, "DNS", "Domain name service"),
    (80, "HTTP", "Standard web server"),
    (110, "POP3", "Mail retrieval"),
    (143, "IMAP", "Mail access"),
    (443, "HTTPS", "Encrypted web server"),
    (445, "SMB", "Windows file sharing (High Risk if exposed publicly)"),
    (3306, "MySQL", "Database service (High Risk if exposed publicly)"),
    (3389, "RDP", "Remote Desktop Protocol (High Risk if exposed publicly)"),
    (5432, "PostgreSQL", "Database service (High Risk if exposed publicly)"),
    (6379, "Redis", "In-memory database (High Risk if exposed publicly)"),
    (8080, "HTTP-Proxy", "Alternative web application port"),
    (8443, "HTTPS-Alt", "Alternative SSL web application port"),
    (27017, "MongoDB", "NoSQL database (High Risk if exposed publicly)")
]

RISKY_PORTS = {445, 3306, 3389, 5432, 6379, 27017, 21}

class PortService:
    @staticmethod
    async def probe_port(host: str, port: int, service_name: str, desc: str) -> Dict[str, Any]:
        result = {
            "port": port,
            "service": service_name,
            "description": desc,
            "open": False,
            "banner": "",
            "is_risky": port in RISKY_PORTS
        }
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.8)
            result["open"] = True
            
            # Try grabbing initial banner (if sent by server like FTP, SSH, SMTP)
            try:
                banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.8)
                result["banner"] = banner_bytes.decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            
            writer.close()
            await writer.wait_closed()
        except Exception:
            result["open"] = False

        return result

    @classmethod
    async def scan_host(cls, target: str) -> Dict[str, Any]:
        target = target.strip().lower()
        results: Dict[str, Any] = {
            "target": target,
            "open_ports": [],
            "closed_count": 0,
            "graph_nodes": [],
            "graph_edges": [],
            "logs": []
        }

        results["logs"].append(f"[INIT] Probing {len(COMMON_PORTS)} strategic attack surface ports on {target}...")

        # Resolve IP first
        try:
            ip = socket.gethostbyname(target)
            results["logs"].append(f"[+] Target resolved to IP: {ip}")
        except Exception:
            ip = target

        tasks = [cls.probe_port(ip, port, svc, desc) for port, svc, desc in COMMON_PORTS]
        scan_results = await asyncio.gather(*tasks)

        for res in scan_results:
            if res["open"]:
                results["open_ports"].append(res)
                risk_tag = "[CRITICAL EXPOSURE]" if res["is_risky"] else "[OPEN]"
                banner_txt = f" - Banner: '{res['banner']}'" if res["banner"] else ""
                results["logs"].append(f"{risk_tag} Port {res['port']}/{res['service']} is OPEN{banner_txt}")

                # Graph node for port/service
                port_node_id = f"port_{ip}_{res['port']}"
                results["graph_nodes"].append({
                    "id": port_node_id,
                    "label": f":{res['port']} ({res['service']})",
                    "type": "open_port",
                    "risk": "critical" if res["is_risky"] else "warning"
                })
                results["graph_edges"].append({
                    "source": f"ip_{ip}",
                    "target": port_node_id,
                    "label": "EXPOSES_SERVICE",
                    "threat": res["is_risky"]
                })
            else:
                results["closed_count"] += 1

        results["logs"].append(f"[SUCCESS] Port audit complete. Found {len(results['open_ports'])} open external services.")
        return results
