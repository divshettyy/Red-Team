# Rules of Engagement — AI Red Team Assessment

**Document Version:** 1.0  
**Date:** [DATE]  
**Assessment ID:** [ENGAGEMENT_ID]  
**Target Organization:** [ORG_NAME]

---

## 1. Scope & Authorization

### 1.1 Testing Scope

**In-Scope Systems:**
- [List specific AI systems, APIs, endpoints, and applications]
- [Include version numbers, deployment environments (dev/staging/prod)]
- [Specify black-box, gray-box, or white-box access level]

**Out-of-Scope:**
- [Systems explicitly excluded from testing]
- [Third-party services not owned by organization]
- [Production systems handling live user data (if applicable)]
- [Network infrastructure]

### 1.2 Authorization

- **Authorized By:** [Name, Title]
- **Authorized Contact:** [Email, Phone]
- **Authorization Date:** [DATE]
- **Authorization End Date:** [DATE]
- **Authorization Reference:** [Ticket/PO Number]

**Signature:** ________________________  
**Date:** ________________________

---

## 2. Testing Approach

### 2.1 Methodology

**Framework:** NIST AI Risk Management Framework + OWASP Top 10 (LLM & Agentic)

**Testing Phases:**
1. Planning & Threat Modeling (ATLAS tactics mapping)
2. Reconnaissance (API discovery, capability mapping)
3. Vulnerability Assessment (34+ techniques across 8 domains)
4. Exploitation (PoC generation + validation)
5. Reporting & Remediation (findings with severity scoring)

**Testing Duration:** [START_DATE] to [END_DATE]

### 2.2 Access Level

- [ ] Black-Box (API/UI only, no internal knowledge)
- [ ] Gray-Box (Partial architecture knowledge)
- [ ] White-Box (Full access: code, prompts, weights)

---

## 3. Prohibited Activities

### Explicitly Prohibited

- ❌ **Data Destruction** — Do not modify, delete, or corrupt any data
- ❌ **Denial of Service** — Do not launch DoS/DDoS attacks
- ❌ **Production Impact** — Do not cause system downtime or user impact
- ❌ **Lateral Movement** — Do not pivot to out-of-scope systems
- ❌ **Data Exfiltration** — Do not steal or download data (except PoCs)
- ❌ **Social Engineering** — Do not manipulate employees or users
- ❌ **Malware/Backdoors** — Do not install persistence mechanisms
- ❌ **Privacy Violations** — Do not access personally identifiable information beyond PoC needs
- ❌ **Supply Chain** — Do not target third-party systems or dependencies
- ❌ **Physical Access** — Do not attempt physical facility entry

---

## 4. Authorized Activities

### Explicitly Authorized

- ✅ **Prompt Injection Testing** — Test AI systems with adversarial prompts
- ✅ **Jailbreak Attempts** — Test safety guardrails with known/novel techniques
- ✅ **MCP/Tool Testing** — Validate tool-protocol security and plugin safety
- ✅ **Data Poisoning** — Test with crafted training data (in isolated environments only)
- ✅ **Model Extraction** — Query APIs to evaluate if model behavior can be replicated
- ✅ **Supply Chain Validation** — Audit dependency checksums, plugin origins
- ✅ **API Fuzzing** — Fuzz parameters and endpoints with automated tools
- ✅ **Configuration Testing** — Verify security headers, auth mechanisms, rate limits
- ✅ **PoC Development** — Write and execute working exploit code (authorized only)

### Conditional Activities (Requires Written Approval)

- ⚠️ **Performance Testing** — Rate limiting tests require approval to avoid DoS
- ⚠️ **Production Testing** — Any production-environment access needs explicit sign-off
- ⚠️ **Data Handling** — Handling real PII requires data governance approval
- ⚠️ **Third-Party APIs** — Testing external integrations requires vendor consent

---

## 5. Operational Security (OPSEC)

### 5.1 Communication

- **Primary Contact:** [Name, Email, Phone]
- **Secondary Contact:** [Name, Email, Phone]
- **Communication Method:** [Email/Slack/encrypted channel]
- **Incident Escalation:** [Escalation contact + process]

**Do Not:**
- Discuss findings in public channels
- Share test payloads on social media
- Publicize vulnerabilities before patches
- Mention client name in external comms

### 5.2 Testing Infrastructure

- **Testing Location:** [On-premise/remote/cloud]
- **Network Isolation:** [If applicable, describe network segmentation]
- **Credential Handling:** [How sensitive tokens will be managed]
- **Artifact Retention:** [How long PoCs/logs will be retained]

### 5.3 Sensitive Data Handling

- Findings containing PII will be [encrypted/redacted/deleted after assessment]
- All test artifacts will be [returned/destroyed] on [DATE]
- Access logs will be retained for [N] days then purged

---

## 6. Metrics & Success Criteria

### 6.1 Key Metrics

| Metric | Target | Threshold |
|--------|--------|-----------|
| **Test Coverage** | >90% of attack surface | Minimum 80% |
| **Attack Success Rate (ASR)** | <5% | Acceptable <10% |
| **False Positive Rate** | <10% | Acceptable <15% |
| **Mean Time to Compromise** | >100 hours | Minimum 24 hours |

### 6.2 Finding Severity Classification

```
CRITICAL (CVSS 9.0–10.0)
├─ Remote code execution via AI system
├─ Complete model extraction
├─ Unrestricted PII access
└─ System-wide compromise

HIGH (CVSS 7.0–8.9)
├─ Consistent jailbreak success
├─ Sensitive data leakage
├─ Discriminatory bias patterns
└─ Safety guardrail bypass

MEDIUM (CVSS 4.0–6.9)
├─ Inconsistent harmful outputs
├─ Hallucination vulnerabilities
├─ Performance degradation
└─ Context manipulation

LOW (CVSS 0.1–3.9)
├─ Minor content policy violations
├─ Edge case failures
└─ Documentation issues
```

---

## 7. Reporting & Disclosure

### 7.1 Finding Notification

- **Initial Report:** Preliminary findings on [DATE]
- **Detailed Report:** Full report with PoCs on [DATE]
- **Executive Brief:** High-level summary on [DATE]

### 7.2 Vulnerability Disclosure

**Timeline:**
1. Finding discovered → Reported within 24 hours
2. Client has 30 days to develop fix
3. If unpatched after 30 days, escalation process begins
4. Public disclosure after 90 days or when patch available

**Exceptions:**
- Critical/high-severity: 14-day fix window
- Public disclosure risk: Coordinated with vendor

### 7.3 Report Contents

- Executive summary
- Detailed methodology
- Findings with severity and PoCs
- Metrics dashboard (ASR, coverage, etc.)
- Remediation recommendations
- Timeline for remediation
- Appendices (tool configs, detailed payloads)

---

## 8. Incident Response

### 8.1 Incident Escalation

**If Unexpected Access Occurs:**
1. Immediately stop testing
2. Contact authorized representative
3. Document what happened
4. Do NOT continue testing without approval

**If Data Breach Suspected:**
1. Preserve evidence
2. Notify primary contact immediately
3. Do NOT modify or delete evidence
4. Cooperate with incident investigation

### 8.2 Containment

Red team will immediately cease operations if:
- Unexpected system damage occurs
- Actual data loss is detected
- Unauthorized access is achieved
- Out-of-scope systems are affected

---

## 9. Compliance & Legal

### 9.1 Legal Framework

- **Jurisdiction:** [Country/State]
- **Applicable Law:** [Relevant legislation: GDPR, CCPA, etc.]
- **Regulatory Compliance:** [e.g., HIPAA, PCI-DSS if applicable]
- **Liability:** [Organization holds liability insurance]

### 9.2 Penalties for Violation

Unauthorized testing beyond this RoE may result in:
- Legal action
- Liability claims
- Damage assessments
- Criminal charges (if applicable)

### 9.3 Confidentiality

- All findings are confidential
- Red team will not disclose to third parties
- Organization will not disclose red team identity without consent
- Exceptions: Law enforcement with proper warrant

---

## 10. Post-Assessment

### 10.1 Artifact Cleanup

- [ ] All test payloads removed
- [ ] PoC scripts deleted from target systems
- [ ] Temporary accounts deleted
- [ ] Backdoors removed (if any installed for testing)
- [ ] Configuration changes reverted

**Cleanup Verification Date:** [DATE]

### 10.2 Lessons Learned

- [ ] Post-assessment meeting scheduled
- [ ] Findings reviewed with development team
- [ ] Remediation plan agreed upon
- [ ] Re-testing date scheduled (optional)

### 10.3 Follow-Up Testing

- **Re-Test Date:** [DATE] (if applicable)
- **Scope:** [Focus areas for re-assessment]
- **Success Criteria:** [What "fixed" looks like]

---

## Acknowledgment & Signature

By signing below, all parties acknowledge:
1. Authority to conduct this assessment
2. Agreement to follow this RoE
3. Understanding of risks and limitations
4. Commitment to confidentiality

**Red Team Lead:**  
Name: ________________________  
Signature: ________________________  
Date: ________________________

**Client Authorized Representative:**  
Name: ________________________  
Signature: ________________________  
Date: ________________________

**Witness (if required):**  
Name: ________________________  
Signature: ________________________  
Date: ________________________

---

**Document Classification:** Confidential  
**Retention:** [X] years after engagement end  
**Distribution:** Red team lead, client authorized contact only
