import httpx
from typing import Dict, Any

class WAFService:
    @staticmethod
    async def detect_waf(domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()
        
        # Enterprise simulation
        if domain == "acme-corp.global":
            return {
                "target": domain,
                "waf_detected": False,
                "waf_name": "None (Direct Origin IP Exposure)",
                "status": "VULNERABLE",
                "risk_level": "HIGH",
                "cdn_provider": "None",
                "origin_ip": "198.51.100.25",
                "signatures": [
                    {"header": "Server", "value": "nginx/1.24.0", "status": "Direct Nginx Web Server (No Reverse Proxy WAF)"},
                    {"header": "CF-RAY", "value": "Missing", "status": "Not routed through Cloudflare edge"},
                    {"header": "X-Amz-Cf-Id", "value": "Missing", "status": "Not routed through AWS CloudFront"}
                ],
                "logs": [
                    f"[WAF-PROBE: INIT] Inspecting edge response headers for {domain}...",
                    f"[!] Alert: No enterprise Web Application Firewall (WAF) detected in traffic flow.",
                    f"[!] Server Header 'nginx/1.24.0' revealed directly without masking.",
                    f"[!] Origin host 198.51.100.25 accepts direct unproxied TCP connections on ports 80/443/3306.",
                    f"[VERDICT] HIGH RISK: Target is exposed to direct Layer 7 DDoS and zero-day exploits without edge filtering."
                ],
                "recommendation": "Deploy a Cloudflare Business/Enterprise or AWS WAF reverse proxy to shield the origin server IP."
            }

        # Real live check
        logs = [f"[WAF-PROBE: INIT] Sending HTTP probe to https://{domain} to identify edge protection..."]
        waf_detected = False
        waf_name = "None Detected"
        status = "UNPROTECTED"
        risk_level = "MEDIUM"
        signatures = []

        try:
            async with httpx.AsyncClient(timeout=4.0, verify=False, follow_redirects=True) as client:
                res = await client.get(f"https://{domain}")
                headers = {k.lower(): v for k, v in res.headers.items()}
                server = headers.get("server", "").lower()

                if "cloudflare" in server or "cf-ray" in headers or "__cfduid" in str(res.cookies):
                    waf_detected = True
                    waf_name = "Cloudflare Enterprise WAF / CDN"
                    status = "PROTECTED"
                    risk_level = "LOW"
                    signatures.append({"header": "Server / CF-Ray", "value": "Cloudflare", "status": "Cloudflare Edge Detected"})
                elif "cloudfront" in str(headers) or "x-amz-cf-id" in headers:
                    waf_detected = True
                    waf_name = "AWS CloudFront WAF"
                    status = "PROTECTED"
                    risk_level = "LOW"
                    signatures.append({"header": "X-Amz-Cf-Id", "value": headers.get("x-amz-cf-id", "Present"), "status": "AWS CloudFront Detected"})
                elif "akamai" in str(headers) or "x-akamai" in str(headers):
                    waf_detected = True
                    waf_name = "Akamai Kona Site Defender"
                    status = "PROTECTED"
                    risk_level = "LOW"
                    signatures.append({"header": "Akamai Edge", "value": "Akamai", "status": "Akamai Edge Detected"})
                elif "fastly" in str(headers) or "x-fastly" in str(headers):
                    waf_detected = True
                    waf_name = "Fastly Next-Gen WAF"
                    status = "PROTECTED"
                    risk_level = "LOW"
                    signatures.append({"header": "Fastly", "value": "Fastly", "status": "Fastly CDN/WAF Detected"})
                else:
                    signatures.append({"header": "Server", "value": headers.get("server", "Unknown"), "status": "No standard WAF signature found"})

                logs.append(f"[+] Edge Server: {headers.get('server', 'Unspecified')}")
                if waf_detected:
                    logs.append(f"[+] Protected by {waf_name}.")
                else:
                    logs.append(f"[WARN] No standard commercial WAF detected. Direct origin connection possible.")

        except Exception as e:
            logs.append(f"[-] HTTP probe error: {str(e)}")

        return {
            "target": domain,
            "waf_detected": waf_detected,
            "waf_name": waf_name,
            "status": status,
            "risk_level": risk_level,
            "signatures": signatures,
            "logs": logs,
            "recommendation": "Maintain edge WAF rules and restrict origin server access to CDN IP ranges."
        }
