"""
Hybrid Detection Engine for Phishing URL Analysis
Purpose: Combine heuristic rules, ML predictions, and threat intelligence APIs
"""

import re
import urllib.parse
import requests
import numpy as np
import pickle
import json
from typing import Dict, Any, Optional, Tuple
import os
from datetime import datetime
import logging
try:
    import tensorflow as tf
    from tensorflow.keras.preprocessing.sequence import pad_sequences
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    tf = None
    pad_sequences = None

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HeuristicAnalyzer:
    """Heuristic rule engine for URL analysis"""
    
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'update', 'confirm', 'secure', 'account', 'login',
            'signin', 'banking', 'paypal', 'amazon', 'microsoft', 'apple',
            'google', 'facebook', 'suspended', 'limited', 'expire', 'urgent'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top']
        
        self.phishing_patterns = [
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP addresses
            r'[a-z]+-[a-z]+-[a-z]+\.',          # Multiple hyphens
            r'[0-9]{5,}',                        # Long numbers
            r'[a-z]{20,}',                       # Very long substrings
        ]
    
    def analyze_url_length(self, url: str) -> float:
        """Analyze URL length (longer URLs more suspicious)"""
        length = len(url)
        if length < 30:
            return 0.0
        elif length < 75:
            return 0.2
        elif length < 150:
            return 0.5
        else:
            return 1.0
    
    def analyze_hyphen_count(self, url: str) -> float:
        """Count hyphens (more hyphens = more suspicious)"""
        hyphen_count = url.count('-')
        return min(hyphen_count / 5.0, 1.0)
    
    def analyze_ip_presence(self, url: str) -> float:
        """Check for IP address in URL"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, url):
            return 1.0
        return 0.0
    
    def analyze_suspicious_keywords(self, url: str) -> float:
        """Check for suspicious keywords"""
        url_lower = url.lower()
        keyword_count = sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
        return min(keyword_count / 3.0, 1.0)
    
    def analyze_subdomain_depth(self, url: str) -> float:
        """Analyze subdomain depth"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain_parts = parsed.netloc.split('.')
            subdomain_count = len(domain_parts) - 2  # Subtract domain and TLD
            
            if subdomain_count <= 1:
                return 0.0
            elif subdomain_count <= 3:
                return 0.3
            else:
                return 0.8
        except:
            return 0.5
    
    def analyze_suspicious_tld(self, url: str) -> float:
        """Check for suspicious TLDs"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    return 0.8
            return 0.0
        except:
            return 0.0
    
    def analyze_phishing_patterns(self, url: str) -> float:
        """Check for common phishing patterns"""
        pattern_count = 0
        for pattern in self.phishing_patterns:
            if re.search(pattern, url):
                pattern_count += 1
        
        return min(pattern_count / 2.0, 1.0)
    
    def analyze_https_usage(self, url: str) -> float:
        """Check HTTPS usage (lack of HTTPS is suspicious)"""
        if url.startswith('https://'):
            return 0.0
        elif url.startswith('http://'):
            return 0.3
        else:
            return 0.5
    
    def calculate_heuristic_score(self, url: str) -> Dict[str, Any]:
        """Calculate comprehensive heuristic score"""
        
        scores = {
            'url_length': self.analyze_url_length(url),
            'hyphen_count': self.analyze_hyphen_count(url),
            'ip_presence': self.analyze_ip_presence(url),
            'suspicious_keywords': self.analyze_suspicious_keywords(url),
            'subdomain_depth': self.analyze_subdomain_depth(url),
            'suspicious_tld': self.analyze_suspicious_tld(url),
            'phishing_patterns': self.analyze_phishing_patterns(url),
            'https_usage': self.analyze_https_usage(url)
        }
        
        # Weighted average (max score = 40)
        weights = {
            'url_length': 0.1,
            'hyphen_count': 0.15,
            'ip_presence': 0.2,
            'suspicious_keywords': 0.2,
            'subdomain_depth': 0.1,
            'suspicious_tld': 0.1,
            'phishing_patterns': 0.1,
            'https_usage': 0.05
        }
        
        weighted_score = sum(scores[key] * weights[key] for key in scores)
        final_score = weighted_score * 40  # Scale to 0-40
        
        return {
            'individual_scores': scores,
            'heuristic_score': final_score,
            'max_heuristic_score': 40
        }

class VirusTotalAPI:
    """VirusTotal API integration for threat intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        
    def is_available(self) -> bool:
        """Check if API key is available"""
        return self.api_key is not None and len(self.api_key) > 0
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """Scan URL with VirusTotal API"""
        if not self.is_available():
            return {
                'api_available': False,
                'api_score': 0,
                'explanation': 'VirusTotal API key not available'
            }
        
        try:
            # URL scan endpoint
            params = {
                'apikey': self.api_key,
                'url': url
            }
            
            response = requests.post(
                f"{self.base_url}/url/scan",
                data=params,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Get scan report
                report_params = {
                    'apikey': self.api_key,
                    'resource': url
                }
                
                report_response = requests.get(
                    f"{self.base_url}/url/report",
                    params=report_params,
                    timeout=10
                )
                
                if report_response.status_code == 200:
                    report = report_response.json()
                    
                    if report.get('response_code') == 1:
                        positives = report.get('positives', 0)
                        total = report.get('total', 1)
                        
                        # Calculate API score (0-20)
                        detection_ratio = positives / total if total > 0 else 0
                        api_score = min(detection_ratio * 20, 20)
                        
                        return {
                            'api_available': True,
                            'api_score': api_score,
                            'positives': positives,
                            'total': total,
                            'detection_ratio': detection_ratio,
                            'explanation': f'VirusTotal: {positives}/{total} engines detected as malicious'
                        }
            
            return {
                'api_available': True,
                'api_score': 0,
                'explanation': 'No VirusTotal data available'
            }
            
        except Exception as e:
            logger.warning(f"VirusTotal API error: {e}")
            return {
                'api_available': False,
                'api_score': 0,
                'explanation': f'VirusTotal API error: {str(e)}'
            }

class MLPredictor:
    """Machine Learning prediction component"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.metadata = None
        self.max_url_length = 200
        
    def load_model(self, model_path: str = None) -> bool:
        """Load the trained model"""
        if not TENSORFLOW_AVAILABLE:
            logger.warning("TensorFlow not available, using fallback prediction")
            return False
            
        try:
            if model_path is None:
                # Find the latest model
                if not os.path.exists('models'):
                    os.makedirs('models', exist_ok=True)
                model_files = [f for f in os.listdir('models') if f.endswith('.h5')]
                if not model_files:
                    logger.warning("No trained model found, using fallback prediction")
                    return False
                
                # Get the latest model file
                latest_model = max(model_files, key=lambda x: os.path.getctime(os.path.join('models', x)))
                base_name = latest_model.replace('.h5', '')
                model_path = f"models/{base_name}"
            
            # Load model
            self.model = tf.keras.models.load_model(f"{model_path}.h5")
            
            # Load tokenizer
            with open(f"{model_path}_tokenizer.pkl", 'rb') as f:
                self.tokenizer = pickle.load(f)
            
            # Load metadata if exists
            try:
                with open(f"{model_path}_metadata.json", 'r') as f:
                    self.metadata = json.load(f)
                    self.max_url_length = self.metadata.get('max_url_length', 200)
            except FileNotFoundError:
                logger.warning("Model metadata not found, using defaults")
            
            logger.info(f"Model loaded successfully from {model_path}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to load model: {e}, using fallback prediction")
            return False
    
    def preprocess_url(self, url: str) -> np.ndarray:
        """Preprocess URL for model prediction"""
        if not TENSORFLOW_AVAILABLE or self.tokenizer is None:
            # Return dummy array for fallback
            return np.array([[0]])
        
        # Convert URL to character sequence
        chars = [c for c in url.lower() if c.isprintable()]
        char_sequence = ' '.join(chars)
        
        # Tokenize
        sequence = self.tokenizer.texts_to_sequences([char_sequence])
        
        # Pad sequence
        padded = pad_sequences(
            sequence,
            maxlen=self.max_url_length,
            padding='post',
            truncating='post'
        )
        
        return padded
    
    def predict(self, url: str) -> Dict[str, Any]:
        """Predict phishing probability"""
        if self.model is None or not TENSORFLOW_AVAILABLE:
            # Use fallback heuristic-based ML prediction
            return self._fallback_prediction(url)
        
        try:
            # Preprocess URL
            processed_url = self.preprocess_url(url)
            
            # Get prediction
            prediction = self.model.predict(processed_url, verbose=0)[0][0]
            
            # Convert to score (0-40)
            ml_score = float(prediction) * 40
            
            return {
                'ml_available': True,
                'ml_probability': float(prediction),
                'ml_score': ml_score,
                'explanation': f'Deep learning model confidence: {prediction:.3f}'
            }
            
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return self._fallback_prediction(url)
    
    def _fallback_prediction(self, url: str) -> Dict[str, Any]:
        """Fallback ML prediction using heuristic features"""
        try:
            # Simple feature-based prediction
            features = self._extract_simple_features(url)
            
            # Simple logistic-like scoring
            score = 0.0
            score += features['suspicious_chars'] * 0.3
            score += features['domain_suspicious'] * 0.4
            score += features['length_suspicious'] * 0.2
            score += features['ip_based'] * 0.5
            
            # Normalize to 0-1
            probability = min(max(score, 0.0), 1.0)
            ml_score = probability * 40
            
            return {
                'ml_available': False,
                'ml_probability': probability,
                'ml_score': ml_score,
                'explanation': f'Fallback heuristic ML prediction: {probability:.3f}'
            }
            
        except Exception as e:
            return {
                'ml_available': False,
                'ml_probability': 0.5,
                'ml_score': 20,
                'explanation': f'Fallback prediction error: {str(e)}'
            }
    
    def _extract_simple_features(self, url: str) -> Dict[str, float]:
        """Extract simple features for fallback prediction"""
        url_lower = url.lower()
        
        # Count suspicious characters
        suspicious_chars = sum(1 for c in url if c in '1234567890!@#$%^&*-_')
        suspicious_chars_score = min(suspicious_chars / 20.0, 1.0)
        
        # Check for suspicious domains
        suspicious_domains = ['bit.ly', '.tk', '.ml', '.ga', '.cf']
        domain_suspicious = 1.0 if any(domain in url_lower for domain in suspicious_domains) else 0.0
        
        # Length-based suspicion
        length_suspicious = 1.0 if len(url) > 80 else (len(url) / 80.0)
        
        # IP-based detection
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_based = 1.0 if re.search(ip_pattern, url) else 0.0
        
        return {
            'suspicious_chars': suspicious_chars_score,
            'domain_suspicious': domain_suspicious,
            'length_suspicious': length_suspicious,
            'ip_based': ip_based
        }

class HybridDetectionEngine:
    """Main hybrid detection engine combining all components"""
    
    def __init__(self, virustotal_api_key: Optional[str] = None):
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.virustotal_api = VirusTotalAPI(virustotal_api_key)
        self.ml_predictor = MLPredictor()
        
        # Try to load ML model
        self.ml_predictor.load_model()
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Perform comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            Complete analysis results with risk score
        """
        try:
            # Parse domain for display
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            
        except:
            domain = "Unknown"
        
        # Heuristic analysis
        heuristic_result = self.heuristic_analyzer.calculate_heuristic_score(url)
        
        # ML prediction
        ml_result = self.ml_predictor.predict(url)
        
        # API analysis (if available)
        api_result = self.virustotal_api.scan_url(url)
        
        # Calculate final risk score
        heuristic_score = heuristic_result['heuristic_score']  # 0-40
        ml_score = ml_result['ml_score']  # 0-40  
        api_score = api_result['api_score']  # 0-20
        
        final_score = heuristic_score + ml_score + api_score
        
        # Determine classification
        if final_score <= 30:
            classification = "Safe"
            risk_level = "Low"
        elif final_score <= 60:
            classification = "Suspicious"
            risk_level = "Medium"
        else:
            classification = "Phishing"
            risk_level = "High"
        
        # Generate explanation
        explanation_parts = []
        
        if heuristic_score > 15:
            explanation_parts.append(f"Heuristic analysis shows suspicious patterns (score: {heuristic_score:.1f}/40)")
        
        if ml_result['ml_available'] and ml_result['ml_probability'] > 0.7:
            explanation_parts.append(f"Deep learning model indicates high phishing probability ({ml_result['ml_probability']:.1%})")
        
        if api_result['api_available'] and api_result.get('positives', 0) > 0:
            explanation_parts.append(f"Threat intelligence APIs detected malicious activity")
        
        if not explanation_parts:
            if final_score <= 30:
                explanation_parts.append("URL appears legitimate based on analysis")
            else:
                explanation_parts.append("URL shows moderate risk indicators")
        
        explanation = ". ".join(explanation_parts) + "."
        
        # Compile results
        result = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'domain': domain,
            'deep_learning_probability': ml_result['ml_probability'],
            'heuristic_score': heuristic_score,
            'api_score': api_score,
            'final_score': final_score,
            'classification': classification,
            'risk_level': risk_level,
            'explanation': explanation,
            'detailed_analysis': {
                'heuristic': heuristic_result,
                'machine_learning': ml_result,
                'threat_intelligence': api_result
            }
        }
        
        return result

def main():
    """Test the hybrid detection engine"""
    print("🔍 Hybrid Phishing Detection Engine Test")
    print("=" * 50)
    
    # Initialize engine
    engine = HybridDetectionEngine()
    
    # Test URLs
    test_urls = [
        "https://www.paypal.com",  # Legitimate
        "http://payp4l-security.com/login",  # Phishing simulation
        "https://192.168.1.1/secure/login",  # IP-based suspicious
        "https://www.google.com",  # Legitimate
        "http://g00gle-verify.suspicious-domain.tk/update"  # Clearly phishing
    ]
    
    for url in test_urls:
        print(f"\n🔗 Analyzing: {url}")
        result = engine.analyze_url(url)
        
        print(f"🏷️  Classification: {result['classification']}")
        print(f"📊 Final Score: {result['final_score']:.1f}/100")
        print(f"💬 Explanation: {result['explanation']}")
        print("-" * 40)

if __name__ == "__main__":
    main()