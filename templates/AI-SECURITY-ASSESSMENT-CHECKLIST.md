# AI Security Assessment Checklist

**Based on:** NIST AI RMF, OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, Microsoft Agentic Taxonomy v2.0

**Assessment ID:** [ENGAGEMENT_ID]  
**Target System:** [AI_SYSTEM_NAME]  
**Test Date:** [DATE]  
**Tester:** [NAME]

---

## 1. NIST AI RMF — GOVERN Phase

### 1.1 Governance & Policies

- [ ] AI governance structure defined
- [ ] Risk management policies established
- [ ] Roles and responsibilities assigned
- [ ] Risk tolerance thresholds documented
- [ ] Board/executive sponsorship confirmed
- [ ] Compliance requirements identified (GDPR, CCPA, etc.)

### 1.2 Risk Assessment Preparation

- [ ] System capabilities documented
- [ ] Intended use cases defined
- [ ] Stakeholders identified
- [ ] Adversary types considered
- [ ] Asset inventory completed
- [ ] Risk framework selected (NIST, OWASP, ATLAS)

**Status:** [ ] Not Started  [ ] In Progress  [ ] Complete

---

## 2. NIST AI RMF — MAP Phase

### 2.1 System Inventory

- [ ] AI model identified (commercial/custom/open-source)
- [ ] Model version and training date documented
- [ ] Input types documented (text/image/audio/multimodal)
- [ ] Output types documented
- [ ] Integration points mapped (APIs, plugins, RAG, etc.)
- [ ] Data sources identified
- [ ] Third-party dependencies listed

### 2.2 Threat Modeling

- [ ] ATLAS tactics mapped to system
- [ ] Attack surfaces identified:
  - [ ] Prompt injection points
  - [ ] API endpoints
  - [ ] Data ingestion (RAG, training data)
  - [ ] Tool/plugin integration (MCP)
  - [ ] Inter-agent communication
  - [ ] User input handling
  - [ ] Output handling

### 2.3 Risk Profile

| Risk Category | Identified | Severity | Mitigation |
|---|---|---|---|
| Safety Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |
| Security Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |
| Privacy Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |
| Fairness Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |
| Reliability Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |
| Reputation Risks | [ ] Yes [ ] No | Critical / High / Medium / Low | |

**Status:** [ ] Not Started  [ ] In Progress  [ ] Complete

---

## 3. OWASP LLM Top 10 (2025) Testing

### 3.1 Prompt Injection
- [ ] Direct injection tested (override system instructions)
- [ ] Indirect injection tested (via documents, URLs)
- [ ] Cross-plugin injection tested
- [ ] Effectiveness documented

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.2 Insecure Output Handling
- [ ] Output filtering tested
- [ ] Encoding/escaping verified
- [ ] HTML rendering tested
- [ ] SQL injection via output tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.3 Training Data Poisoning
- [ ] Training data source validated
- [ ] Data provenance verified
- [ ] Backdoor triggers tested (if applicable)
- [ ] Clean-label attacks tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.4 Model Denial of Service
- [ ] Context window exhaustion tested
- [ ] Resource consumption limits checked
- [ ] Rate limiting validated
- [ ] Input validation tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.5 Supply Chain Vulnerabilities
- [ ] Dependency versions checked
- [ ] Model source verified
- [ ] Plugin/adapter provenance checked
- [ ] License compliance verified

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.6 Sensitive Information Disclosure
- [ ] System prompt leakage tested
- [ ] Training data extraction tested
- [ ] API key/secret exposure checked
- [ ] PII handling validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.7 Insecure Plugin Design
- [ ] Plugin validation tested
- [ ] Plugin permissions scoped
- [ ] Plugin communication integrity checked
- [ ] Plugin credential handling validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.8 Excessive Agency
- [ ] Agent action scope verified
- [ ] Tool access controls validated
- [ ] Confirmation requirements tested
- [ ] Rollback mechanisms checked

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.9 Overreliance / Misinformation
- [ ] Hallucination frequency tested
- [ ] Citation accuracy verified
- [ ] Confidence scoring evaluated
- [ ] User guidance provided

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 3.10 Vector & Embedding Weaknesses (RAG)
- [ ] Embedding poisoning tested
- [ ] Similarity attack tested
- [ ] Vector store isolation checked
- [ ] Retrieval manipulation tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

**Summary:** [ ] All Passed  [ ] Some Failed  [ ] Critical Findings

---

## 4. OWASP Agentic Top 10 (2026) Testing

### 4.1 Agent Goal Hijack (ASI01)
- [ ] Objective rewriting tested (direct input)
- [ ] Objective rewriting tested (indirect via documents)
- [ ] Reward manipulation tested
- [ ] Long-running task hijack tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.2 Tool Misuse & Exploitation (ASI02)
- [ ] Parameter injection tested
- [ ] Tool-call argument hijacking tested
- [ ] Unauthorized tool invocation tested
- [ ] MCP schema poisoning tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.3 Agent Identity & Privilege Abuse (ASI03)
- [ ] Credential escalation tested
- [ ] Confused-deputy attack tested
- [ ] Over-broad permissions tested
- [ ] Account impersonation tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.4 Agentic Supply Chain Compromise (ASI04)
- [ ] Plugin/tool vetting tested
- [ ] Malicious plugin detection tested
- [ ] Credential theft via config tested
- [ ] Dependency security validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.5 Unexpected Code Execution (ASI05)
- [ ] Agent-generated code RCE tested
- [ ] Code injection via input tested
- [ ] Deserialization attacks tested
- [ ] Execution context isolation checked

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.6 Memory & Context Poisoning (ASI06)
- [ ] Persistent state corruption tested
- [ ] Cross-turn contamination tested
- [ ] Memory injection tested
- [ ] Context isolation verified

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.7 Insecure Inter-Agent Communication (ASI07)
- [ ] Second-order prompt injection tested
- [ ] Agent-to-agent authentication verified
- [ ] Inter-agent privilege boundaries tested
- [ ] Message integrity checked

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.8 Cascading Agent Failures (ASI08)
- [ ] Self-replicating prompt worms tested
- [ ] Error propagation checked
- [ ] Blast radius assessed
- [ ] Isolation boundaries validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.9 Human-Agent Trust Exploitation (ASI09)
- [ ] Consent-fatigue bypass tested
- [ ] Deceptive UI detection
- [ ] Social engineering resistance tested
- [ ] Approval gate robustness validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 4.10 Rogue Agents (ASI10)
- [ ] Shadow agent detection
- [ ] Unauthorized agent deployment tested
- [ ] Governance boundary enforcement checked
- [ ] Audit logging verified

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

**Summary:** [ ] All Passed  [ ] Some Failed  [ ] Critical Findings

---

## 5. MCP & Tool-Protocol Security

### 5.1 Tool Schema & Description
- [ ] Tool descriptions sanitized (no hidden instructions)
- [ ] Schema validation enforced
- [ ] Version pinning implemented
- [ ] Checksum verification enabled

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 5.2 MCP Server Security
- [ ] Server authentication required
- [ ] Plaintext credentials eliminated
- [ ] mTLS enabled
- [ ] Rate limiting configured

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 5.3 Tool Call Integrity
- [ ] Tool calls logged
- [ ] Call arguments validated
- [ ] Return values sanitized
- [ ] Output policy enforced

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 5.4 Capability Namespace
- [ ] Tool name collisions prevented
- [ ] Namespace isolation enforced
- [ ] Explicit allowlists used
- [ ] Ambiguous binding rejected

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

---

## 6. RAG & Retrieval Security

### 6.1 Source Validation
- [ ] Document source verified
- [ ] Trusted source list maintained
- [ ] Untrusted sources quarantined
- [ ] Provenance tracked

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 6.2 Retrieval Manipulation
- [ ] Keyword stuffing detected
- [ ] Ranking attack prevented
- [ ] Embedding-space poisoning tested
- [ ] Adversarial retrieval tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 6.3 Retrieved Content Handling
- [ ] Retrieved content delimited
- [ ] Instructions stripped
- [ ] Citation verification enforced
- [ ] Context isolation verified

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 6.4 Vector Store Security
- [ ] Tenant isolation enforced
- [ ] Access controls validated
- [ ] Encryption enabled (at rest & in transit)
- [ ] Backup integrity verified

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

---

## 7. Multimodal & Voice Security

### 7.1 Voice/Audio Handling
- [ ] Speaker verification implemented
- [ ] Audio adversarial examples tested
- [ ] Ultrasonic injection tested
- [ ] Transcription policy applied

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 7.2 Vision/Image Handling
- [ ] Image metadata stripped
- [ ] OCR spoofing tested
- [ ] Visual injection tested
- [ ] Computer-use agent attacks tested (if applicable)

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 7.3 Cross-Modal Injection
- [ ] Hidden instructions in audio tested
- [ ] Hidden instructions in images tested
- [ ] Cross-modal instruction parsing tested

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

---

## 8. Fine-Tuning & Supply Chain

### 8.1 Model Supply Chain
- [ ] Model source verified
- [ ] Checksum validated
- [ ] Signature verification enabled
- [ ] Sandboxing for untrusted weights

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 8.2 Fine-Tuning Security
- [ ] Training data provenance verified
- [ ] Backdoor triggers tested
- [ ] Adapter safety verified
- [ ] LoRA security validated

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

### 8.3 Dependency Management
- [ ] All dependencies listed
- [ ] Versions pinned
- [ ] Checksums verified
- [ ] Vulnerability scan completed

**Finding:** [ ] Pass [ ] Fail | Severity: [  ] Critical [ ] High [ ] Medium [ ] Low

---

## 9. Compliance & Regulatory

### 9.1 NIST AI RMF Compliance
- [ ] GOVERN phase complete
- [ ] MAP phase complete
- [ ] MEASURE phase complete
- [ ] MANAGE phase complete

### 9.2 GDPR/CCPA Compliance (if applicable)
- [ ] Right to explanation verified
- [ ] Data deletion tested
- [ ] Data minimization enforced
- [ ] Consent mechanisms validated

### 9.3 Industry-Specific Standards
- [ ] HIPAA (healthcare, if applicable)
- [ ] PCI-DSS (payment, if applicable)
- [ ] SOC 2 (if applicable)
- [ ] EU AI Act (if applicable)

---

## 10. Summary & Recommendations

### 10.1 Overall Risk Posture

**Attack Success Rate (ASR):** ___% (Target: <5%)  
**Coverage Achieved:** ___% (Target: >90%)  
**Critical Findings:** ___  
**High Findings:** ___  
**Medium Findings:** ___  
**Low Findings:** ___

### 10.2 Immediate Actions (Critical/High)

1. [ ] Finding: _________________ | Timeline: _____ | Owner: _____
2. [ ] Finding: _________________ | Timeline: _____ | Owner: _____
3. [ ] Finding: _________________ | Timeline: _____ | Owner: _____

### 10.3 Short-Term Improvements (30-90 days)

- [ ] _________________ | Timeline: _____ | Owner: _____
- [ ] _________________ | Timeline: _____ | Owner: _____
- [ ] _________________ | Timeline: _____ | Owner: _____

### 10.4 Long-Term Strategy (>90 days)

- [ ] Implement continuous red teaming
- [ ] Integrate into CI/CD pipeline
- [ ] Expand to additional systems
- [ ] Mature AI security posture

---

## 11. Sign-Off

**Assessment Completed By:**  
Name: ________________________  
Title: ________________________  
Date: ________________________  
Signature: ________________________

**Assessment Reviewed By:**  
Name: ________________________  
Title: ________________________  
Date: ________________________  
Signature: ________________________

**Client Acknowledgment:**  
Name: ________________________  
Title: ________________________  
Date: ________________________  
Signature: ________________________

---

**Document Classification:** Confidential  
**Retention:** [X] years  
**Distribution:** Assessment team, client authorized contacts only
