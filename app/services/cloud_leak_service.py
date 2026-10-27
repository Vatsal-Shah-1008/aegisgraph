import httpx
from typing import Dict, Any, List

class CloudLeakService:
    @staticmethod
    async def scan_cloud_and_secrets(domain: str) -> Dict[str, Any]:
        domain = domain.strip().lower()
        base_name = domain.split('.')[0]

        # Preset demo scenario for acme-corp.global
        if domain == "acme-corp.global":
            return {
                "domain": domain,
                "total_probed": 6,
                "leaks_detected": 3,
                "cloud_assets": [
                    {
                        "resource": f"{base_name}-database-backups.s3.amazonaws.com",
                        "type": "AWS S3 Bucket",
                        "status": "PUBLIC_READ",
                        "risk": "CRITICAL",
                        "details": "Exposed bucket listing contains corporate database dumps: 'prod_db_backup_2025.sql.gz' (420 MB)"
                    },
                    {
                        "resource": f"https://dev-stage.{domain}/.env",
                        "type": "Exposed Environment File",
                        "status": "EXPOSED",
                        "risk": "CRITICAL",
                        "details": "Exposed configuration file leaks: DB_PASSWORD, AWS_ACCESS_KEY_ID, STRIPE_SECRET_KEY"
                    },
                    {
                        "resource": f"https://api.{domain}/swagger.json",
                        "type": "Public API Schema",
                        "status": "DISCLOSED",
                        "risk": "MEDIUM",
                        "details": "Internal API endpoints and authentication parameter schemas fully revealed to public"
                    },
                    {
                        "resource": f"{base_name}-assets.s3.amazonaws.com",
                        "type": "AWS S3 Bucket",
                        "status": "RESTRICTED",
                        "risk": "SAFE",
                        "details": "Bucket correctly configured with private ACL (HTTP 403 Access Denied)"
                    },
                    {
                        "resource": f"https://{domain}/robots.txt",
                        "type": "Disclosed Crawler Paths",
                        "status": "INFO",
                        "risk": "LOW",
                        "details": "Reveals unlinked staging directories: Disallow: /admin-v2/, /staging-auth/"
                    }
                ],
                "logs": [
                    f"[INIT] Scanning for exposed cloud buckets and secret files on {domain}...",
                    f"[!] CRITICAL LEAK: AWS S3 Bucket '{base_name}-database-backups' allows Public Read Access!",
                    f"[!] CRITICAL EXPOSURE: Found publicly readable '.env' file leaking database secrets on dev-stage.{domain}!",
                    f"[+] API Schema Disclosed: Swagger endpoints mapped on api.{domain}",
                    f"[+] S3 Bucket '{base_name}-assets' is securely private (403)",
                    f"[SUCCESS] Cloud sweep complete. 2 Critical Leaks require immediate cloud IAM remediation."
                ]
            }

        # Real live inspection for other domains
        cloud_results = []
        logs = [f"[INIT] Initiating non-intrusive cloud posture and sensitive path probe for {domain}..."]
        
        # Test sensitive paths
        paths_to_test = [
            ("/.env", "Environment Config File"),
            ("/robots.txt", "Web Crawler Directives"),
            ("/swagger.json", "OpenAPI Documentation"),
            ("/.git/HEAD", "Exposed Git Repository")
        ]

        async with httpx.AsyncClient(timeout=3.5, verify=False, follow_redirects=True) as client:
            for path, desc in paths_to_test:
                url = f"https://{domain}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        is_leak = path in ["/.env", "/.git/HEAD"]
                        cloud_results.append({
                            "resource": url,
                            "type": desc,
                            "status": "EXPOSED" if is_leak else "DISCLOSED",
                            "risk": "CRITICAL" if is_leak else "INFO",
                            "details": f"Endpoint reachable with HTTP 200 (Length: {len(resp.text)} bytes)"
                        })
                        logs.append(f"{'[!] LEAK' if is_leak else '[+] FOUND'}: {url} is accessible (HTTP 200)")
                    elif resp.status_code == 403:
                        cloud_results.append({
                            "resource": url,
                            "type": desc,
                            "status": "RESTRICTED",
                            "risk": "SAFE",
                            "details": "Access Forbidden (HTTP 403)"
                        })
                except Exception:
                    pass

        # Check public S3 bucket
        s3_url = f"https://{base_name}-public.s3.amazonaws.com"
        try:
            async with httpx.AsyncClient(timeout=2.5) as client:
                resp = await client.get(s3_url)
                if resp.status_code == 200:
                    cloud_results.append({
                        "resource": f"{base_name}-public.s3.amazonaws.com",
                        "type": "AWS S3 Bucket",
                        "status": "PUBLIC_READ",
                        "risk": "CRITICAL",
                        "details": "Publicly listable S3 storage bucket discovered."
                    })
                    logs.append(f"[!] CRITICAL: Publicly accessible S3 bucket found at {s3_url}")
                elif resp.status_code == 403:
                    cloud_results.append({
                        "resource": f"{base_name}-public.s3.amazonaws.com",
                        "type": "AWS S3 Bucket",
                        "status": "RESTRICTED",
                        "risk": "SAFE",
                        "details": "Bucket exists but access is restricted (403)"
                    })
        except Exception:
            pass

        logs.append(f"[SUCCESS] Cloud Hunter scanned {len(paths_to_test) + 1} cloud assets. {len([r for r in cloud_results if r['risk'] == 'CRITICAL'])} critical leaks found.")

        return {
            "domain": domain,
            "total_probed": len(paths_to_test) + 1,
            "leaks_detected": len([r for r in cloud_results if r["risk"] == "CRITICAL"]),
            "cloud_assets": cloud_results,
            "logs": logs
        }
