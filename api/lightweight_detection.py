"""
Lightweight Detection Engine for Serverless Deployment
Purpose: Robust heuristic phishing detection without heavy ML dependencies
"""

import re
import urllib.parse
import socket
import requests
import os
import logging
import math
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

class LightweightDetectionEngine:
    """Lightweight heuristic-based phishing detection for serverless deployment"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        
        # Brand names commonly impersonated in phishing
        self.brand_names = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
            'instagram', 'twitter', 'linkedin', 'dropbox', 'netflix', 'spotify',
            'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
            'dhl', 'fedex', 'usps', 'ups', 'walmart', 'ebay', 'adobe',
            'office365', 'outlook', 'yahoo', 'aol', 'icloud', 'whatsapp',
            'telegram', 'coinbase', 'binance', 'blockchain', 'steam', 'roblox',
        ]
        
        # Legitimate root domains (exact match only)
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'paypal.com', 'netflix.com', 'dropbox.com',
            'github.com', 'linkedin.com', 'twitter.com', 'x.com',
            'instagram.com', 'youtube.com', 'wikipedia.org', 'reddit.com',
            'stackoverflow.com', 'yahoo.com', 'bing.com', 'live.com',
            'outlook.com', 'office.com', 'spotify.com', 'twitch.tv',
            'adobe.com', 'zoom.us', 'slack.com', 'notion.so',
            'chase.com', 'wellsfargo.com', 'bankofamerica.com',
            'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
        }
        
        # Suspicious TLDs commonly abused
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq',           # free TLDs
            '.top', '.click', '.download', '.work',        # cheap TLDs
            '.buzz', '.xyz', '.club', '.icu', '.cam',      # commonly abused
            '.loan', '.win', '.bid', '.stream', '.racing', # spam TLDs
            '.review', '.trade', '.date', '.faith',        # more spam
            '.zip', '.mov',                                # confusing TLDs
        ]
        
        # Phishing keywords in URL path / params
        self.phishing_keywords = [
            'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
            'secure', 'security', 'update', 'confirm', 'account', 'suspend',
            'locked', 'expired', 'urgent', 'alert', 'warning', 'password',
            'credential', 'authenticate', 'validate', 'restore', 'recover',
            'unusual', 'unauthorized', 'billing', 'invoice', 'payment',
            'wallet', 'bank', 'ssn', 'social-security',
        ]
        
        # URL shortener domains
        self.shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd',
            'buff.ly', 'ow.ly', 'short.link', 'rb.gy', 'cutt.ly',
            'shorturl.at', 'tiny.cc', 'bc.vc', 'x.co',
        ]
        
        # Suspicious patterns (regex)
        self.brand_phishing_patterns = [
            r'paypal.*(?:secure|update|verify|login|confirm)',
            r'amazon.*(?:account|suspend|verify|order)',
            r'apple.*(?:id|locked|verify|icloud)',
            r'microsoft.*(?:security|alert|office|login)',
            r'google.*(?:verify|security|drive|account)',
            r'facebook.*(?:disabled|account|verify)',
            r'netflix.*(?:payment|update|billing|account)',
            r'(?:bank|chase|wells).*(?:secure|verify|login|alert)',
        ]
    
    def _get_root_domain(self, domain: str) -> str:
        """Extract root domain (e.g., 'www.sub.example.com' -> 'example.com')"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for phishing indicators using lightweight heuristics"""
        start_time = datetime.now()
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower().split(':')[0]  # remove port
            path = parsed.path.lower()
            query = parsed.query.lower()
            full_url = url.lower()
            root_domain = self._get_root_domain(domain)
            
            # Skip scoring for known-legitimate exact root domains
            is_known_legit = root_domain in self.legitimate_domains
            
            # Run all checks
            heuristic_scores = {
                'domain_spoofing': self._check_domain_spoofing(domain, root_domain, is_known_legit),
                'suspicious_patterns': self._check_suspicious_patterns(full_url, domain, path, query),
                'url_structure': self._check_url_structure(full_url, domain, path, query),
                'suspicious_tld': self._check_suspicious_tld(domain, root_domain),
                'ip_address': self._check_ip_address(domain),
            }
            
            # Known-legitimate domains get a big reduction (but not zero — spoofed subdomains still count)
            if is_known_legit:
                for k in heuristic_scores:
                    if k != 'domain_spoofing':
                        heuristic_scores[k] = 0
                heuristic_scores['domain_spoofing'] = 0
            
            # Cap raw heuristic at 40
            heuristic_score = min(sum(heuristic_scores.values()), 40)
            
            # VirusTotal (0-20)
            api_score = self._check_virustotal(url) if self.api_key else 0
            
            # Final score: map raw (max 60) to 0-100
            raw_score = heuristic_score + api_score
            final_score = min(round(raw_score / 60 * 100), 100)
            
            deep_learning_probability = round(final_score / 100, 4)
            
            if final_score >= 60:
                classification = "phishing"
                risk_level = "high"
            elif final_score >= 35:
                classification = "suspicious"
                risk_level = "medium"
            else:
                classification = "legitimate"
                risk_level = "low"
            
            explanation = self._generate_explanation(heuristic_scores, api_score, classification)
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'domain': domain,
                'deep_learning_probability': deep_learning_probability,
                'heuristic_score': heuristic_score,
                'api_score': api_score,
                'final_score': final_score,
                'classification': classification,
                'risk_level': risk_level,
                'explanation': explanation,
                'processing_time_ms': processing_time,
                'detailed_analysis': {
                    'heuristic_breakdown': heuristic_scores,
                    'domain_analysis': {
                        'is_ip': self._is_ip_address(domain),
                        'subdomain_count': len(domain.split('.')) - 2,
                        'root_domain': root_domain,
                        'is_known_legitimate': is_known_legit,
                    },
                    'url_features': {
                        'length': len(url),
                        'has_https': url.startswith('https://'),
                        'phishing_keyword_count': sum(1 for kw in self.phishing_keywords if kw in full_url),
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return {
                'success': False,
                'error': f"Analysis failed: {str(e)}",
                'url': url,
                'timestamp': datetime.now().isoformat()
            }
    
    # ---------- HEURISTIC CHECKS (each returns 0-20 range, total capped at 40) ----------

    def _check_domain_spoofing(self, domain: str, root_domain: str, is_known_legit: bool) -> float:
        """Detect brand impersonation and domain spoofing"""
        if is_known_legit:
            return 0
        
        score = 0
        
        # Check if any brand name appears in domain but it's NOT the real domain
        for brand in self.brand_names:
            brand_real_domain = f"{brand}.com"
            if brand in domain and root_domain != brand_real_domain:
                score += 12
                # Extra penalty if brand is in subdomain (e.g., paypal.evil.com)
                if brand in domain.replace(root_domain, ''):
                    score += 5
                break  # one brand match is enough
        
        # Typosquatting: character substitution (0→o, 1→l, etc.)
        typo_map = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '@': 'a', '!': 'i'}
        decoded_domain = domain
        for fake, real in typo_map.items():
            decoded_domain = decoded_domain.replace(fake, real)
        
        if decoded_domain != domain:
            # After decoding, does it match a brand?
            for brand in self.brand_names:
                if brand in decoded_domain and brand not in domain:
                    score += 15  # strong typosquatting signal
                    break
        
        # Homograph-like: brand name with extra chars (e.g., paypa1, g00gle)
        for brand in self.brand_names:
            if len(brand) >= 4:
                # Check if domain contains most of brand's chars in order (fuzzy)
                ratio = self._char_match_ratio(brand, domain)
                if ratio > 0.75 and root_domain != f"{brand}.com":
                    score += 8
                    break
        
        # Domain contains hyphen-separated brand words (paypal-login.com)
        for brand in self.brand_names:
            if re.search(rf'{brand}[\-_]', domain) and root_domain != f"{brand}.com":
                score += 10
                break
        
        return min(score, 20)
    
    def _char_match_ratio(self, brand: str, domain: str) -> float:
        """Simple fuzzy match: what fraction of brand chars appear in-order in domain"""
        bi = 0
        for ch in domain:
            if bi < len(brand) and ch == brand[bi]:
                bi += 1
        return bi / len(brand) if brand else 0

    def _check_suspicious_patterns(self, url: str, domain: str, path: str, query: str) -> float:
        """Check for phishing patterns in the URL"""
        score = 0
        
        # Brand + action patterns (very strong signal)
        for pattern in self.brand_phishing_patterns:
            if re.search(pattern, url):
                score += 10
                break
        
        # Phishing keywords in path or query
        keyword_hits = sum(1 for kw in self.phishing_keywords if kw in path or kw in query)
        if keyword_hits >= 3:
            score += 10
        elif keyword_hits >= 2:
            score += 6
        elif keyword_hits >= 1:
            score += 3
        
        # Data URI or javascript: scheme
        if url.startswith('data:') or url.startswith('javascript:'):
            score += 15
        
        # Contains @ symbol (credential harvesting trick)
        if '@' in url and '@' in url.split('//')[1] if '//' in url else False:
            score += 10
        
        # Double slashes in path (redirect trick)
        if '//' in path:
            score += 5
        
        # Hex/encoded characters abuse
        pct_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
        if pct_encoded > 5:
            score += 5
        
        return min(score, 20)

    def _check_url_structure(self, url: str, domain: str, path: str, query: str) -> float:
        """Analyze URL structure anomalies"""
        score = 0
        
        # Very long URL
        if len(url) > 200:
            score += 5
        elif len(url) > 100:
            score += 2
        
        # Excessive subdomains (more than 2 levels)
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count >= 4:
            score += 8
        elif subdomain_count >= 3:
            score += 5
        elif subdomain_count >= 2:
            score += 2
        
        # No HTTPS
        if not url.startswith('https://'):
            score += 4
        
        # URL shortener
        for shortener in self.shorteners:
            if shortener in domain:
                score += 5
                break
        
        # Deeply nested path (3+ levels)
        path_depth = len([p for p in path.split('/') if p])
        if path_depth >= 5:
            score += 4
        elif path_depth >= 3:
            score += 2
        
        # Query string with suspicious params
        if query:
            susp_params = ['redirect', 'url', 'next', 'return', 'goto', 'dest', 'redir']
            for p in susp_params:
                if p in query:
                    score += 3
                    break
        
        # File extensions in URL that don't belong
        bad_exts = ['.exe', '.scr', '.zip', '.rar', '.bat', '.cmd', '.msi']
        for ext in bad_exts:
            if ext in path:
                score += 6
                break
        
        # Unusual port
        if ':' in domain:
            port = domain.split(':')[1]
            if port not in ['80', '443', '8080', '8443']:
                score += 4
        
        return min(score, 15)
    
    def _check_suspicious_tld(self, domain: str, root_domain: str) -> float:
        """Check for suspicious top-level domains"""
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return 12
        
        # Double TLD tricks (e.g., .com.tk)
        if re.search(r'\.(com|org|net|gov)\.[a-z]{2,}$', domain):
            return 8
        
        return 0
    
    def _check_ip_address(self, domain: str) -> float:
        """Check if domain is an IP address"""
        if self._is_ip_address(domain.split(':')[0]):
            return 15
        # Hex or octal IP obfuscation
        if re.match(r'^0x[0-9a-f]+', domain) or re.match(r'^\d{8,}$', domain):
            return 15
        return 0
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if string is an IP address"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False
    
    def _check_virustotal(self, url: str) -> float:
        """Check URL against VirusTotal API"""
        if not self.api_key:
            return 0
        
        try:
            params = {'apikey': self.api_key, 'resource': url}
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/url/report',
                params=params, timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 1)
                    if positives > 0:
                        return min((positives / total) * 20, 20)
        except Exception as e:
            logger.warning(f"VirusTotal API error: {e}")
        
        return 0
    
    def _generate_explanation(self, scores: Dict[str, float], api_score: float, classification: str) -> str:
        """Generate human-readable explanation"""
        parts = []
        
        if classification == "phishing":
            parts.append("🚨 HIGH RISK: This URL shows strong indicators of being a phishing attempt.")
        elif classification == "suspicious":
            parts.append("⚠️ SUSPICIOUS: This URL has concerning characteristics.")
        else:
            parts.append("✅ LEGITIMATE: This URL appears to be safe.")
        
        if scores.get('domain_spoofing', 0) > 0:
            parts.append("Domain impersonates a well-known brand.")
        if scores.get('suspicious_patterns', 0) > 0:
            parts.append("Contains phishing keywords or patterns.")
        if scores.get('ip_address', 0) > 0:
            parts.append("Uses an IP address instead of a domain name.")
        if scores.get('suspicious_tld', 0) > 0:
            parts.append("Uses a top-level domain commonly abused in phishing.")
        if scores.get('url_structure', 0) > 0:
            parts.append("URL structure has anomalous characteristics.")
        if api_score > 0:
            parts.append("Flagged by external threat intelligence.")
        
        return " ".join(parts)