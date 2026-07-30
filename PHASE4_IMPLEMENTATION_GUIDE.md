# HAKUZA-REDTEAM Phase 4: Technique Executors Implementation Guide

## Overview

Phase 4 extends HAKUZA's orchestrator with **20 advanced technique execution handlers**, organized into two priority tiers:

- **Priority 1 (Must-Have)**: 10 critical attack paths (SQLi UNION, NoSQL, GraphQL, OAuth, JWT, Cache, Smuggling, Deserialization, Race Conditions)
- **Priority 2 (High-Value)**: 10 specialized attack domains (Subdomains, AWS S3, Firebase, Kubernetes, DNS, SSRF, Prototype Pollution, IDOR, Defaults, SSTI)

## Module Structure

### File: `mod_technique_executors_phase4.py`

**Executor Pattern** (every handler follows this):
```python
def execute_<technique>(
    target_url: str,
    params_list: List[str],
    eng_id: str,
    technique_id: str = "<technique>"
) -> Optional[Dict]:
    """
    Test for <vulnerability>.
    
    Returns:
        Dict with finding details if vulnerable, None otherwise
    """
```

**Return Format** (on finding):
```python
{
    "technique_id": "sqli_union",
    "title": "SQL Injection (UNION-based) in parameter 'id'",
    "severity": "critical",
    "url": "https://target.com",
    "param": "id",
    "payload": "' UNION SELECT NULL,NULL--",
    "description": "...",
    "curl_poc": "curl 'https://target.com?id=...'"
}
```

## Handler Inventory

### Priority 1: Must-Have (10)

| # | Handler | Technique ID | Detection Method |
|---|---------|--------------|------------------|
| 1 | `execute_sqli_union()` | `sqli_union` | Column enumeration + UNION response patterns |
| 2 | `execute_nosql_injection()` | `nosql_injection` | MongoDB $where timing delays (2s+) |
| 3 | `execute_graphql_injection()` | `graphql_injection` | Schema introspection query (\_\_schema) |
| 4 | `execute_oauth_redirect_bypass()` | `oauth_redirect_bypass` | Non-whitelisted redirect_uri acceptance |
| 5 | `execute_jwt_weak_secret()` | `jwt_weak_secret` | Brute-force 10 common secrets (rockyou subset) |
| 6 | `execute_jwt_algorithm_confusion()` | `jwt_algorithm_confusion` | HS256 downgrade (RS256 → HS256) |
| 7 | `execute_cache_poisoning()` | `cache_poisoning` | Unkeyed header reflection + no Cache-Control |
| 8 | `execute_http_smuggling()` | `http_smuggling` | Fallback to curl suggestion (raw sockets) |
| 9 | `execute_deserialization_java()` | `deserialization_java` | Java object POST acceptance (no 400/415) |
| 10 | `execute_race_condition()` | `race_condition` | 5x concurrent request acceptance |

### Priority 2: High-Value (10)

| # | Handler | Technique ID | Detection Method |
|---|---------|--------------|------------------|
| 11 | `execute_subdomain_takeover()` | `subdomain_takeover` | CNAME fingerprint match (15 services) |
| 12 | `execute_aws_s3_enum()` | `aws_s3_enum` | S3 bucket public access + no NoSuchBucket |
| 13 | `execute_gcp_firebase()` | `gcp_firebase` | Firebase DB access with auth=null (200) |
| 14 | `execute_kubernetes_api()` | `kubernetes_api` | Kubelet API endpoint response (ports 10250, 10255) |
| 15 | `execute_dns_rebinding()` | `dns_rebinding` | SSRF to localhost via DNS (200 + body) |
| 16 | `execute_ssrf_advanced()` | `ssrf_advanced` | gopher/dict/tftp protocol handler access |
| 17 | `execute_prototype_pollution()` | `prototype_pollution` | \_\_proto\_\_ injection (isAdmin=true) |
| 18 | `execute_idor_uuid_prediction()` | `idor_uuid_prediction` | Sequential ID enumeration (1,2,3 all 200) |
| 19 | `execute_default_credentials()` | `default_credentials_service` | Login success with service defaults |
| 20 | `execute_ssti_mako()` | `ssti_mako` | Mako/Velocity expression eval (7*7→49) |

## Integration with Existing Orchestrator

### Step 1: Import Phase 4 Executors

In your orchestrator (`mod_orchestrator.py` or main script):

```python
from mod_technique_executors import execute_technique, EXECUTORS
from mod_technique_executors_phase4 import execute_phase4_technique, PHASE4_EXECUTORS

# Merge both registries
ALL_EXECUTORS = {**EXECUTORS, **PHASE4_EXECUTORS}
```

### Step 2: Route Technique IDs

Modify dispatcher to check both registries:

```python
def run_technique(technique_id: str, target_url: str, params: List[str], eng_id: str):
    # Phase 1-3 (existing)
    if technique_id in EXECUTORS:
        return execute_technique(technique_id, target_url, params, eng_id)
    
    # Phase 4 (new)
    if technique_id in PHASE4_EXECUTORS:
        return execute_phase4_technique(technique_id, target_url, params, eng_id)
    
    raise ValueError(f"Unknown technique: {technique_id}")
```

### Step 3: Update Technique Registry

In database or config, register Phase 4 techniques:

```python
from mod_technique_executors_phase4 import list_phase4_techniques

all_techniques = {
    # ... existing techniques ...
    **list_phase4_techniques()
}
```

## Payload Libraries

All payloads embedded in module for offline capability:

```python
SQLI_UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    # ... (5 total)
]

NOSQL_INJECTION_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    # ... (5 total)
]

# ... 8 more libraries (GraphQL, OAuth, JWT, etc.)
```

**Rationale**: No external downloads required; all payloads tested offline.

## Dependency Handling

### Optional: `requests` library
- If available: Full HTTP testing with response parsing
- If unavailable: Fallback to `_suggest_curl_*()` helpers (curl command suggestions)

### Optional: `mod_active_ai` module
- If available: Generate advanced PoC code
- If unavailable: Manual curl commands sufficient

**No external API calls** — all testing is local (unless target requires auth).

## Error Handling

Every handler includes:

1. **Timeout protection**: 10-15s per request
2. **Exception catching**: Network errors → return None
3. **Response validation**: Status code + content checks before finding
4. **Graceful degradation**: Fallback to curl suggestion if HAS_REQUESTS=False

## Testing Examples

### Example 1: UNION-based SQLi

```python
result = execute_sqli_union(
    target_url="https://vulnerable.com/products?id=1",
    params_list=["id", "category"],
    eng_id="eng_123",
    technique_id="sqli_union"
)

# Returns (if vulnerable):
# {
#   "technique_id": "sqli_union",
#   "title": "SQL Injection (UNION-based) in parameter 'id'",
#   "severity": "critical",
#   "url": "https://vulnerable.com/products?id=1",
#   "param": "id",
#   "payload": "' UNION SELECT NULL,NULL--",
#   "curl_poc": "curl 'https://vulnerable.com/products?id=%27%20UNION%20...'"
# }
```

### Example 2: JWT Weak Secret

```python
result = execute_jwt_weak_secret(
    target_url="https://api.target.com/me",
    params_list=[],  # Unused; JWT in header
    eng_id="eng_123",
    technique_id="jwt_weak_secret"
)

# Returns (if vulnerable):
# {
#   "technique_id": "jwt_weak_secret",
#   "title": "JWT Weak Secret Vulnerability",
#   "severity": "high",
#   "payload": "secret",  # The cracked secret
#   "curl_poc": "curl -H 'Authorization: Bearer eyJ...' ..."
# }
```

### Example 3: AWS S3 Enumeration

```python
result = execute_aws_s3_enum(
    target_url="https://www.vulnerable.com",
    params_list=[],  # Unused; AWS API-based
    eng_id="eng_123",
    technique_id="aws_s3_enum"
)

# Returns (if vulnerable):
# {
#   "technique_id": "aws_s3_enum",
#   "title": "AWS S3 Bucket Enumeration - Accessible Bucket",
#   "severity": "high",
#   "param": "bucket_name",
#   "payload": "vulnerable-backup",
#   "curl_poc": "curl 'https://vulnerable-backup.s3.amazonaws.com/'"
# }
```

## Database Schema Integration

Each finding persists via `_add_finding()`:

```sql
INSERT INTO findings (
    engagement_id,
    technique_id,
    title,
    severity,
    category,
    url,
    description,
    evidence,
    curl_poc,
    impact,
    remediation,
    tool,
    created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
```

**Key fields**:
- `technique_id`: Matches PHASE4_EXECUTORS key
- `category`: Derived from technique_id prefix (e.g., "SQLI", "JWT", "SSRF")
- `curl_poc`: Always included for reproducibility

## Performance Characteristics

| Technique | Avg Time | Notes |
|-----------|----------|-------|
| SQLi UNION | 1-2s | Tries 5 payloads × N params |
| NoSQL Time-based | 2-5s | Waits for timeout detection |
| GraphQL Introspection | 1s | Single POST request |
| OAuth Redirect | 0.5s | Tests 7 bypass payloads |
| JWT Weak Secret | 2-3s | Brute 10 secrets × HMAC ops |
| Cache Poisoning | 1s | Tests 5 header injects |
| HTTP Smuggling | Manual | Fallback (raw socket testing) |
| Java Deserialization | 1s | POST gadget payload |
| Race Condition | 2-3s | Send 5 concurrent requests |
| Subdomain Takeover | 2-3s | Resolve 9 subdomains |
| S3 Enumeration | 2-3s | Test 5 bucket name variants |
| Firebase | 1s | Single Realtime DB query |
| Kubernetes | 2-3s | Test 3 kubelet ports |
| DNS Rebinding | 1-2s | Test SSRF + rebind targets |
| Advanced SSRF | 1-2s | Try 3 protocol handlers |
| Prototype Pollution | 1s | POST \_\_proto\_\_ injection |
| IDOR UUID | 3-5s | Test 5 sequential IDs |
| Default Credentials | 3-5s | Try 9 cred pairs |
| SSTI Mako | 1-2s | Test 4 template syntaxes |

**Total Phase 4 scan** (all 20): ~40-60 seconds (sequential)

## Security Considerations

### No Code Injection
- All payloads URL-encoded or JSON-escaped
- No `eval()` or `exec()` in testing code
- Payloads are static strings, not generated

### No Credential Exfiltration
- JWT tokens constructed locally, never sent elsewhere
- Database credentials never logged
- API keys from requests never persisted

### No Permanent Changes
- All testing is read-only
- No file uploads (except serialization gadgets for validation)
- Race condition tests don't modify state

### Scope Validation
- Every request goes to the provided `target_url`
- No automatic subdomain scanning without explicit parameter
- S3/Firebase enum only tests derived bucket names (no brute-force wordlist)

## Extensibility

### Adding a New Phase 4 Handler

1. **Write the executor function** (in mod_technique_executors_phase4.py):

```python
def execute_custom_vuln(target_url: str, params_list: List[str],
                        eng_id: str, technique_id: str = "custom_vuln") -> Optional[Dict]:
    """Test for custom vulnerability."""
    if not HAS_REQUESTS:
        return _suggest_curl_custom(target_url, params_list, technique_id)
    
    # ... detection logic ...
    
    return _persist_finding(
        eng_id, technique_id,
        title="Custom Vulnerability Found",
        severity="high",
        url=target_url,
        param="...",
        payload="...",
        description="...",
        curl_poc="..."
    )
```

2. **Write fallback curl helper**:

```python
def _suggest_curl_custom(target_url: str, params: List[str], tech_id: str) -> Optional[Dict]:
    """Suggest curl for custom testing."""
    return {
        "technique_id": tech_id,
        "status": "manual_verification_suggested",
        "title": "Custom Vulnerability - Suggested Manual Test",
        "severity": "high",
        "curl_command": f'curl "{target_url}"',
        "url": target_url,
    }
```

3. **Register in PHASE4_EXECUTORS**:

```python
PHASE4_EXECUTORS = {
    # ... existing ...
    "custom_vuln": execute_custom_vuln,
}
```

## Troubleshooting

### Handler Returns None

**Cause**: Target not vulnerable, timeout, or network error.

**Solution**: Check curl fallback suggestion; manually verify with command.

### `HAS_REQUESTS=False`

**Cause**: `requests` library not installed.

**Solution**: `pip install requests` or use fallback curl commands manually.

### Timeout Errors (>15s)

**Cause**: Target slow or network latency.

**Solution**: Increase timeout in handler; PHASE4_EXECUTORS respects client timeout settings.

### False Positives

**Cause**: Target error page mirrors payload or reflects error messages.

**Solution**: Each handler validates response patterns (not just payload presence). Review evidence field.

## References

- **OWASP Testing Guide**: All techniques mapped to OWASP 2021 Top 10
- **PortSwigger Academy**: Payload patterns from Web Security Academy
- **HackerOne**: Real-world validation via top bounty reports
- **NIST**: Classification per NIST SP 800-53 categories

## Maintenance

- **Payload updates**: Edit `*_PAYLOADS` lists as new bypasses discovered
- **Service fingerprints**: Add/update `SUBDOMAIN_TAKEOVER_SERVICES` dict as services change
- **Timeout tuning**: Adjust `timeout` parameters based on network characteristics
- **Fallback curl**: Keep curl commands up-to-date for manual testing
