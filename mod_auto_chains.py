#!/usr/bin/env python3
"""
HAKUZA Auto-Chains - Automated exploitation chain discovery
Connects vulnerabilities into multi-step compromise paths
Example: XSS → Session Hijacking → Admin Access → Database → RCE
"""

import json
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

class Impact(Enum):
    CONFIDENTIALITY = "C"
    INTEGRITY = "I"
    AVAILABILITY = "A"

@dataclass
class Finding:
    id: str
    technique_id: str
    severity: str
    cvss_score: float
    artifacts: Dict[str, str]  # curl_poc, poc_file, etc.

@dataclass
class Chain:
    steps: List[str]  # List of technique IDs
    impact: Set[Impact]
    likelihood: float  # 0-1
    required_artifacts: List[str]
    cumulative_cvss: float
    description: str

class ExploitationChainBuilder:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.findings = {}
        self.chains = []
        
        # Define known chaining patterns
        self.patterns = self._build_patterns()

    def _build_patterns(self) -> Dict[str, List[Tuple[str, str]]]:
        """Define known exploitation chains: source_technique → sink_technique"""
        return {
            # Web → Database → RCE
            "web_to_rce": [
                ("xss_reflected", "sqli_error"),
                ("sqli_error", "rfi_execution"),
                ("sqli_error", "lfi_traversal"),
            ],
            
            # Authentication bypass → Privilege escalation
            "auth_to_admin": [
                ("jwt_none_alg", "mass_assignment"),
                ("default_credentials", "mass_assignment"),
            ],
            
            # SSRF → Cloud → Credentials
            "ssrf_to_cloud": [
                ("ssrf_cloud_metadata", "aws_s3_enum"),
                ("ssrf_cloud_metadata", "gcp_firebase"),
            ],
            
            # File read → Source code → RCE
            "file_to_code": [
                ("lfi_traversal", "rfi_execution"),
            ],
            
            # Race condition → Logic bypass
            "race_to_bypass": [
                ("race_condition", "business_logic_flaw"),
            ],
        }

    def add_finding(self, finding: Finding) -> None:
        """Register a finding for chain discovery"""
        self.findings[finding.id] = finding

    def discover_chains(self, findings: List[Finding], depth: int = 3) -> List[Chain]:
        """Auto-discover exploitation chains from findings"""
        
        # Build findings dict
        for finding in findings:
            self.add_finding(finding)
        
        chains = []
        
        # For each finding, try to chain with others
        for source_finding in findings:
            for sink_finding in findings:
                if source_finding.id == sink_finding.id:
                    continue
                
                # Check if there's a known chain pattern
                for pattern_type, patterns in self.patterns.items():
                    for src_tech, sink_tech in patterns:
                        if source_finding.technique_id == src_tech and sink_finding.technique_id == sink_tech:
                            # Build the chain
                            chain = Chain(
                                steps=[source_finding.technique_id, sink_finding.technique_id],
                                impact=self._calculate_impact(source_finding, sink_finding),
                                likelihood=self._calculate_likelihood(source_finding, sink_finding),
                                required_artifacts=self._get_required_artifacts(source_finding, sink_finding),
                                cumulative_cvss=source_finding.cvss_score + (sink_finding.cvss_score * 0.5),
                                description=f"{source_finding.technique_id} → {sink_finding.technique_id}"
                            )
                            chains.append(chain)
        
        # Sort by impact (CVSS + likelihood)
        chains.sort(key=lambda c: c.cumulative_cvss * c.likelihood, reverse=True)
        
        return chains[:10]  # Top 10 chains

    def _calculate_impact(self, finding1: Finding, finding2: Finding) -> Set[Impact]:
        """Determine combined impact of chained findings"""
        impacts = set()
        
        if finding1.cvss_score >= 7 or finding2.cvss_score >= 7:
            impacts.add(Impact.CONFIDENTIALITY)
            impacts.add(Impact.INTEGRITY)
        
        if "rce" in finding2.technique_id.lower() or "admin" in finding2.technique_id.lower():
            impacts.add(Impact.INTEGRITY)
            impacts.add(Impact.AVAILABILITY)
        
        return impacts

    def _calculate_likelihood(self, finding1: Finding, finding2: Finding) -> float:
        """Estimate success probability of chaining"""
        # High severity + required artifacts = high likelihood
        severity_scores = {"critical": 0.95, "high": 0.75, "medium": 0.5, "low": 0.3}
        
        score1 = severity_scores.get(finding1.severity.lower(), 0.5)
        score2 = severity_scores.get(finding2.severity.lower(), 0.5)
        
        # Both must be successful for chain to work
        likelihood = score1 * score2
        
        # Reduce likelihood if artifacts missing
        if not finding1.artifacts.get("curl_poc"):
            likelihood *= 0.7
        
        return min(likelihood, 1.0)

    def _get_required_artifacts(self, finding1: Finding, finding2: Finding) -> List[str]:
        """Determine what data must flow from finding1 to finding2"""
        artifacts = []
        
        # XSS → need session cookie
        if "xss" in finding1.technique_id and "sql" in finding2.technique_id:
            artifacts.append("session_cookie")
        
        # SSRF → need response parsing
        if "ssrf" in finding1.technique_id:
            artifacts.append("ssrf_response_data")
        
        # File read → need source code parsing
        if "lfi" in finding1.technique_id or "traversal" in finding1.technique_id:
            artifacts.append("file_content")
        
        return artifacts

    def validate_chain(self, chain: Chain) -> bool:
        """Verify chain execution order makes sense"""
        
        # Check if all steps have required artifacts
        for step in chain.steps:
            finding = self.findings.get(step)
            if not finding:
                return False
            
            if finding.artifacts.get("curl_poc") is None:
                return False
        
        return True

    def execute_chain_simulation(self, chain: Chain) -> Dict:
        """Simulate chain execution (dry run)"""
        
        results = {
            "chain_id": "-".join(chain.steps),
            "steps_executed": 0,
            "data_flow": [],
            "success": True,
            "blockers": [],
        }
        
        # Step 1: Execute first technique
        first_tech = self.findings.get(chain.steps[0])
        if first_tech and first_tech.artifacts.get("curl_poc"):
            results["steps_executed"] += 1
            results["data_flow"].append({
                "step": 1,
                "technique": chain.steps[0],
                "output": "curl_poc_executed",
            })
        else:
            results["success"] = False
            results["blockers"].append("First technique has no PoC")
        
        # Step 2+: Execute subsequent techniques with data from previous
        for i in range(1, len(chain.steps)):
            prev_tech = self.findings.get(chain.steps[i-1])
            curr_tech = self.findings.get(chain.steps[i])
            
            if curr_tech and prev_tech:
                # Check data compatibility
                if chain.required_artifacts:
                    results["data_flow"].append({
                        "step": i+1,
                        "technique": chain.steps[i],
                        "input": chain.required_artifacts,
                        "output": "data_extracted",
                    })
                    results["steps_executed"] += 1
            else:
                results["success"] = False
                results["blockers"].append(f"Missing finding for step {i+1}")
        
        return results

# Integration with HAKUZA
def build_chains(engagement_id: str, findings_list: List[Dict]) -> List[Dict]:
    """Main entry point for HAKUZA"""
    
    builder = ExploitationChainBuilder(engagement_id)
    
    # Convert findings dicts to Finding objects
    findings = []
    for f in findings_list:
        finding = Finding(
            id=f.get("id"),
            technique_id=f.get("technique_id"),
            severity=f.get("severity", "medium"),
            cvss_score=float(f.get("cvss_score", 5.0)),
            artifacts=f.get("artifacts", {})
        )
        findings.append(finding)
    
    # Discover chains
    chains = builder.discover_chains(findings)
    
    # Validate and simulate
    valid_chains = []
    for chain in chains:
        if builder.validate_chain(chain):
            simulation = builder.execute_chain_simulation(chain)
            valid_chains.append({
                "steps": chain.steps,
                "impact": [i.value for i in chain.impact],
                "likelihood": chain.likelihood,
                "cumulative_cvss": chain.cumulative_cvss,
                "description": chain.description,
                "simulation": simulation,
            })
    
    return sorted(valid_chains, key=lambda c: c["cumulative_cvss"] * c["likelihood"], reverse=True)

