# HAKUZA Zeroday Miner — AI-Powered Vulnerability Pattern Discovery

## Overview

The **Zeroday Miner** discovers undocumented vulnerability patterns from:
- GitHub exploit repositories (trending exploits & PoCs)
- CVE databases (recent vulnerability disclosures)
- Shodan honeypots (emerging attack vectors)
- PoC code analysis (AST-based pattern extraction)
- Pattern generalization (1 exploit → 100 variants via AI)
- Novelty detection (techniques unknown to HAKUZA's 250+)
- Automatic YAML technique generation

**Target**: 20-50 new patterns monthly, 10-50x finding amplification.

## Quick Start

```bash
# Full scan: GitHub + CVE + Shodan
python3 mod_zeroday_miner.py --full-scan

# GitHub only (fast)
python3 mod_zeroday_miner.py --scan-github

# Save to custom output
python3 mod_zeroday_miner.py --full-scan --output ./new_techniques.yaml
```

## Components

### 1. GitHubExploitScanner
Mines trending exploits from GitHub API
- Filters by stars (min 50) and recency (7-30 days)
- Infers vulnerability type from metadata
- Deduplicates by URL

### 2. CVEPatternMatcher
Extracts patterns from CVE descriptions
- Fetches recent CVEs from NVD API
- Infers vulnerability type from text
- Extracts keywords and attack vectors
- Maps CVSS to severity

### 3. ShodanTrendAnalyzer
Identifies emerging attack vectors
- Searches Shodan honeypot data
- Analyzes service exposure trends
- Correlates with known vulnerabilities
- Requires `SHODAN_API_KEY`

### 4. PoCCodeAnalyzer
AST-based pattern extraction from exploit code
- Python: AST parsing for imports, functions, dangerous calls
- JavaScript: Regex-based DOM sink and network call detection
- Payload extraction from string literals

### 5. VulnerabilityPatternExtractor
Generalizes 1 exploit → 100 variants
- Heuristic generalization (parameterization)
- AI generalization via Claude (semantic variants)
- Polyglot payloads (XSS, SQLi, RCE contexts)
- Framework-specific exploitation

### 6. NovelVulnDetector
Identifies techniques not in HAKUZA's 250+
- Novelty score (0-1) based on CWE/keyword overlap
- Detects novel technique combinations
- Filters patterns with novelty > 0.5

### 7. AutomaticTechniqueCreation
Generates YAML technique definitions
- Converts patterns to HAKUZA format
- AI-powered procedure description
- Includes indicators, artifacts, MITRE/CWE mappings

### 8. ZerodayMiner (Orchestrator)
Multi-phase discovery pipeline:
1. Mine GitHub exploits
2. Extract CVE patterns
3. Analyze Shodan trends
4. Generalize patterns
5. Assess novelty
6. Generate techniques YAML

## Environment Variables

```bash
export GITHUB_TOKEN="ghp_xxxxx"        # Optional (rate limits)
export SHODAN_API_KEY="key"            # Required for Shodan
export ANTHROPIC_API_KEY="sk-ant-..."  # For AI generalization
```

## Testing

```bash
# Run 20+ comprehensive tests
pytest test_zeroday_miner.py -v

# With coverage
pytest test_zeroday_miner.py --cov=mod_zeroday_miner
```

## Example Output

```yaml
techniques:
  - id: zeroday_abc123
    name: "Novel DOM-based XSS via eval()"
    severity: high
    cvss: 7.5
    novelty_score: 0.85
    confidence: 0.9
    indicators: ["eval(", "innerHTML", "Function"]
    variants: [v1, v2, v3, ...]
    sources:
      - github:https://github.com/example/exploit
      - cve:CVE-2024-1234
```

## Performance

- GitHub scan: 10-30s
- CVE extraction: 15-45s
- Pattern generalization: 30-120s per pattern (AI)
- Full scan: 2-10 minutes

## Integration

Results saved to `~/.hakuza/zeroday_patterns/` for automated HAKUZA integration.

**Author**: Divith D Shetty | Version: 1.0.0
