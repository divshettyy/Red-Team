#!/usr/bin/env python3
"""
HAKUZA Secrets Hunter - Aggressive credential & hardcoded secret discovery
Finds: API keys, DB passwords, private keys, tokens, hardcoded IPs, etc.
Patterns from: TruffleHog, detect-secrets, git-secrets, and real-world findings
"""

import re
import os
import json
import base64
import hashlib
from typing import List, Dict, Tuple, Optional
from pathlib import Path
from datetime import datetime

# High-entropy detection patterns
PATTERNS = {
    "aws_access_key": r"(?i)aws_access_key_id\s*[=:]\s*([A-Z0-9]{20})",
    "aws_secret_key": r"(?i)aws_secret_access_key\s*[=:]\s*([A-Za-z0-9/+=]{40})",
    "github_token": r"(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,255}",
    "gitlab_token": r"(?i)(glpat-|glcbt-)[A-Za-z0-9_\-]{20,}",
    "slack_token": r"(?i)xo[ab]b-[0-9a-z]{10,32}-[0-9a-z]{32}",
    "stripe_key": r"sk_live_[A-Za-z0-9]{24}",
    "private_key": r"-----BEGIN( ENCRYPTED)? (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY",
    "database_url": r"(?i)(postgres|mysql|mongodb)://[^\s]+:[^\s]+@",
    "jwt_token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_\-]*",
    "api_key_generic": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
    "password_hardcoded": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    "firebase_key": r"AIza[0-9A-Za-z\-_]{35}",
    "gcp_key": r"ya29\.[A-Za-z0-9_\-]{100,}",
    "azure_key": r"[A-Za-z0-9+/]{88}==",  # Base64 88-char keys
    "twilio_key": r"SK[a-z0-9]{32}",
    "hex_private_key": r"(?i)['\"]?[0-9a-f]{64}['\"]?(?i:.*hex|.*key)",
}

class SecretsHunter:
    def __init__(self, engagement_id: str):
        self.engagement_id = engagement_id
        self.secrets_found = []
        self.timestamp = datetime.now().isoformat()

    def analyze_file(self, filepath: str) -> List[Dict]:
        """Analyze single file for secrets"""
        secrets = []
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    for pattern_name, pattern in PATTERNS.items():
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            # Extract the secret value
                            secret_value = match.group(1) if match.lastindex else match.group(0)
                            
                            # Calculate entropy (higher = more random = more likely secret)
                            entropy = self._calculate_entropy(secret_value)
                            
                            if entropy > 3.5 or pattern_name in ['private_key', 'jwt_token']:
                                secrets.append({
                                    'file': filepath,
                                    'line': line_no,
                                    'pattern': pattern_name,
                                    'value': secret_value[:50] + ('...' if len(secret_value) > 50 else ''),
                                    'entropy': entropy,
                                    'severity': 'CRITICAL' if entropy > 4.5 else 'HIGH',
                                    'context': line.strip()[:100],
                                })
        except Exception as e:
            pass
        
        return secrets

    def analyze_repository(self, repo_path: str) -> List[Dict]:
        """Recursively analyze repository for secrets"""
        secrets = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common unimportant directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', '.venv']]
            
            for file in files:
                # Skip binary files
                if any(file.endswith(ext) for ext in ['.png', '.jpg', '.gif', '.pdf', '.zip']):
                    continue
                
                filepath = os.path.join(root, file)
                file_secrets = self.analyze_file(filepath)
                secrets.extend(file_secrets)
        
        return secrets

    def _calculate_entropy(self, value: str) -> float:
        """Shannon entropy - higher = more random/secret-like"""
        if not value:
            return 0
        
        # Count unique characters
        char_counts = {}
        for char in value:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(value)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * (probability and __import__('math').log2(probability))
        
        return entropy

    def report_secrets(self, secrets: List[Dict]) -> Dict:
        """Generate findings for hakuza database"""
        if not secrets:
            return {"count": 0, "findings": []}
        
        # Group by severity
        critical = [s for s in secrets if s['severity'] == 'CRITICAL']
        high = [s for s in secrets if s['severity'] == 'HIGH']
        
        findings = {
            'engagement_id': self.engagement_id,
            'total': len(secrets),
            'critical': len(critical),
            'high': len(high),
            'timestamp': self.timestamp,
            'secrets': secrets[:20],  # Top 20 for brevity
        }
        
        return findings

# Integration with HAKUZA
def hunt_secrets(engagement_id: str, target_path: str) -> Dict:
    """Main entry point for HAKUZA"""
    hunter = SecretsHunter(engagement_id)
    
    if os.path.isfile(target_path):
        secrets = hunter.analyze_file(target_path)
    else:
        secrets = hunter.analyze_repository(target_path)
    
    return hunter.report_secrets(secrets)

