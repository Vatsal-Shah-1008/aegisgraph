from fastapi import APIRouter, Query
from app.services.correlation_service import CorrelationService
from app.services.dns_service import DNSService

router = APIRouter(prefix="/api/ai", tags=["AI Copilot"])

@router.get("/copilot/analyze")
def analyze_target(domain: str = Query(...)):
    dns_res = DNSService.resolve_domain(domain)
    correlation = CorrelationService.correlate_findings(domain=domain, dns_data=dns_res)
    return {
        "domain": domain,
        "analysis": correlation["ai_copilot_verdict"],
        "findings": correlation["findings"],
        "risk_score": correlation["overall_risk_score"],
        "recommended_action": correlation["findings"][0]["remediation"] if correlation["findings"] else "No critical actions needed."
    }
