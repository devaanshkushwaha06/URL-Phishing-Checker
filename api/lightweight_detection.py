"""
Lightweight Detection Engine for Serverless Deployment
Purpose: Simplified phishing detection without heavy ML dependencies
"""

import re
import urllib.parse
import socket
import requests
import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class LightweightDetectionEngine:
    """Lightweight heuristic-based phishing detection for serverless deployment"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        
        # Common phishing patterns
        self.suspicious_patterns = [
            r'paypal.*secure.*update',
            r'amazon.*account.*suspended',
            r'apple.*id.*locked',
            r'microsoft.*security.*alert',
            r'google.*verify.*account',
            r'facebook.*disabled.*account',
            r'instagram.*suspended.*account',
            r'twitter.*security.*check',
            r'linkedin.*account.*restricted',
            r'dropbox.*storage.*full',
            r'netflix.*payment.*failed',
            r'spotify.*premium.*expired'
        ]
        
        # Suspicious TLDs and domains
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download', '.work']
        self.legitimate_domains = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 
                                 'amazon.com', 'paypal.com', 'netflix.com', 'dropbox.com']
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for phishing indicators using lightweight heuristics
        
        Returns:
            Dict containing analysis results
        """
        start_time = datetime.now()
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Initialize scores
            heuristic_scores = {
                'domain_spoofing': 0,
                'suspicious_patterns': 0,
                'url_structure': 0,
                'suspicious_tld': 0,
                'ip_address': 0
            }
            
            # Check for domain spoofing
            heuristic_scores['domain_spoofing'] = self._check_domain_spoofing(domain)
            
            # Check for suspicious patterns
            heuristic_scores['suspicious_patterns'] = self._check_suspicious_patterns(url.lower())
            
            # Check URL structure
            heuristic_scores['url_structure'] = self._check_url_structure(url, domain, path)
            
            # Check for suspicious TLD
            heuristic_scores['suspicious_tld'] = self._check_suspicious_tld(domain)
            
            # Check if domain is IP address
            heuristic_scores['ip_address'] = self._check_ip_address(domain)
            
            # Calculate final heuristic score (0-40)
            heuristic_score = sum(heuristic_scores.values())
            
            # Get VirusTotal score if available
            api_score = self._check_virustotal(url) if self.api_key else 0
            
            # Calculate final score (0-100)
            final_score = min(heuristic_score + api_score, 100)
            
            # Determine classification and risk level
            if final_score >= 70:
                classification = "phishing"
                risk_level = "high"
            elif final_score >= 40:
                classification = "suspicious" 
                risk_level = "medium"
            else:
                classification = "legitimate"
                risk_level = "low"
            
            # Generate explanation
            explanation = self._generate_explanation(heuristic_scores, api_score, classification)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return {
                'success': True,
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'domain': domain,
                'deep_learning_probability': 0.0,  # Not available in lightweight version
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
                        'domain_age': 'unknown'  # Would require additional API
                    },
                    'url_features': {
                        'length': len(url),
                        'has_https': url.startswith('https://'),
                        'suspicious_keywords': len([p for p in self.suspicious_patterns if re.search(p, url.lower())])
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
    
    def _check_domain_spoofing(self, domain: str) -> float:
        """Check for domain spoofing attempts"""
        score = 0
        
        for legit_domain in self.legitimate_domains:
            if legit_domain in domain and domain != legit_domain:
                # Check for common spoofing techniques
                if any(char in domain for char in ['0', '1', '-']):
                    score += 15  # High suspicion
                elif domain.replace(legit_domain, '') in ['.com', '.net', '.org', '.co']:
                    score += 10  # Medium suspicion
                else:
                    score += 5   # Low suspicion
        
        return min(score, 20)
    
    def _check_suspicious_patterns(self, url: str) -> float:
        """Check for suspicious patterns in URL"""
        score = 0
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url):
                score += 8
        
        return min(score, 15)
    
    def _check_url_structure(self, url: str, domain: str, path: str) -> float:
        """Analyze URL structure for suspicious elements"""
        score = 0
        
        # Very long URLs
        if len(url) > 150:
            score += 5
        
        # Too many subdomains
        subdomain_count = len(domain.split('.')) - 2
        if subdomain_count > 3:
            score += 3
        
        # Suspicious keywords in path
        suspicious_keywords = ['secure', 'verify', 'update', 'suspended', 'locked', 'confirm']
        for keyword in suspicious_keywords:
            if keyword in path:
                score += 2
        
        # URL shorteners (basic check)
        shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl']
        if any(shortener in domain for shortener in shorteners):
            score += 3
        
        return min(score, 10)
    
    def _check_suspicious_tld(self, domain: str) -> float:
        """Check for suspicious top-level domains"""
        score = 0
        
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 8
                break
        
        return score
    
    def _check_ip_address(self, domain: str) -> float:
        """Check if domain is an IP address"""
        if self._is_ip_address(domain):
            return 12  # High suspicion for IP-based URLs
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
            response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', 
                                  params=params, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    positives = result.get('positives', 0)
                    total = result.get('total', 1)
                    
                    if positives > 0:
                        return min((positives / total) * 60, 60)  # Scale to 0-60
            
        except Exception as e:
            logger.warning(f"VirusTotal API error: {e}")
        
        return 0
    
    def _generate_explanation(self, scores: Dict[str, float], api_score: float, classification: str) -> str:
        """Generate human-readable explanation"""
        explanations = []
        
        if classification == "phishing":
            explanations.append("🚨 HIGH RISK: This URL shows strong indicators of being a phishing attempt.")
        elif classification == "suspicious":
            explanations.append("⚠️ SUSPICIOUS: This URL has some concerning characteristics.")
        else:
            explanations.append("✅ LEGITIMATE: This URL appears to be safe.")
        
        if scores['domain_spoofing'] > 0:
            explanations.append("Domain spoofing detected - mimics legitimate brands.")
        
        if scores['suspicious_patterns'] > 0:
            explanations.append("Contains suspicious keywords commonly used in phishing.")
        
        if scores['ip_address'] > 0:
            explanations.append("Uses IP address instead of domain name.")
        
        if scores['suspicious_tld'] > 0:
            explanations.append("Uses suspicious top-level domain.")
        
        if api_score > 0:
            explanations.append("Flagged by external threat intelligence.")
        
        return " ".join(explanations)