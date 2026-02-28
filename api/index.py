"""
Vercel Serverless API Entry Point for Phishing URL Detection System
Purpose: FastAPI application configured for Vercel deployment
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import csv

# Setup logging for Vercel FIRST - before any other imports that use logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the project root to the Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PROJECT_ROOT)

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

# Import admin router
try:
    from services.admin_api import admin_router
    logger.info("Successfully imported admin_router")
except Exception as e:
    logger.warning(f"Could not import admin_router: {e}")
    admin_router = None

# Import detection engine
_engine_source = "none"
try:
    from api.lightweight_detection import LightweightDetectionEngine as DetectionEngine
    _engine_source = "api.lightweight_detection"
    logger.info("Imported DetectionEngine from api.lightweight_detection")
except Exception:
    try:
        from lightweight_detection import LightweightDetectionEngine as DetectionEngine
        _engine_source = "lightweight_detection"
        logger.info("Imported DetectionEngine from lightweight_detection (direct)")
    except Exception as e:
        logger.error(f"FAILED to import DetectionEngine: {e}")
        DetectionEngine = None

# Initialize FastAPI app
app = FastAPI(
    title="AI Phishing Detection API",
    description="Hybrid deep learning + heuristic phishing URL detection system",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Startup event handler
@app.on_event("startup")
async def startup_event():
    """Log startup information"""
    logger.info("=== FastAPI Application Starting ===")
    logger.info(f"DetectionEngine available: {DetectionEngine is not None}")
    logger.info(f"Python version: {sys.version}")
    logger.info("Application ready to receive requests")

# Configure CORS for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount admin router
if admin_router:
    app.include_router(admin_router)
    logger.info("Admin router mounted at /admin")

# Global detection engine
detection_engine = None

# Pydantic models
class URLScanRequest(BaseModel):
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL cannot be empty')
        
        v = v.strip()
        if not (v.startswith('http://') or v.startswith('https://') or v.startswith('ftp://')):
            v = 'https://' + v
        
        if len(v) > 2000:
            raise ValueError('URL too long (max 2000 characters)')
            
        return v

class URLScanResponse(BaseModel):
    success: bool
    timestamp: str
    url: str
    domain: str
    deep_learning_probability: float
    heuristic_score: float
    api_score: float
    final_score: float
    classification: str
    risk_level: str
    explanation: str
    processing_time_ms: float
    detailed_analysis: Optional[Dict[str, Any]] = None

class FeedbackRequest(BaseModel):
    url: str
    correct_label: int  # 0 = legitimate, 1 = phishing
    user_comment: Optional[str] = None
    confidence_level: Optional[int] = None  # 1-5 rating for validation
    user_expertise: Optional[str] = None    # beginner, intermediate, expert
    
    @field_validator('correct_label')
    @classmethod
    def validate_label(cls, v):
        if v not in [0, 1]:
            raise ValueError('correct_label must be 0 (legitimate) or 1 (phishing)')
        return v
    
    @field_validator('confidence_level')
    @classmethod
    def validate_confidence(cls, v):
        if v is not None and (v < 1 or v > 5):
            raise ValueError('confidence_level must be between 1 and 5')
        return v

class FeedbackResponse(BaseModel):
    success: bool
    message: str
    feedback_id: str
    validation_status: str  # pending, approved, rejected

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    components: Optional[Dict[str, str]] = None

# Root API endpoint
@app.get("/")
async def root():
    """Root API endpoint"""
    return {"message": "AI Phishing Detection API", "status": "running"}

@app.get("/api")
async def api_root():
    """API root endpoint"""
    return {"message": "AI Phishing Detection API", "status": "running", "version": "1.0.0"}

# Initialize detection engine on first request
def get_detection_engine():
    global detection_engine
    if detection_engine is None:
        virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        if DetectionEngine:
            detection_engine = DetectionEngine(virustotal_key)
        else:
            # Fallback for serverless - create a mock detection engine
            logger.warning("Detection engine not available, using fallback")
            detection_engine = MockDetectionEngine()
    return detection_engine

class MockDetectionEngine:
    """Enhanced fallback detection engine for serverless environment"""
    def analyze_url(self, url: str) -> Dict[str, Any]:
        import re
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            full_url = url.lower()
        except:
            domain = url.split('/')[2] if '://' in url else url.split('/')[0]
            path = ''
            full_url = url.lower()
        
        risk_score = 0
        risk_factors = []
        
        # Suspicious keywords (weighted)
        high_risk_keywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'netflix', 'facebook']
        suspicious_keywords = ['login', 'verify', 'secure', 'update', 'confirm', 'suspend', 'urgent', 'expired']
        
        for keyword in high_risk_keywords:
            if keyword in full_url and keyword not in domain:
                risk_score += 40
                risk_factors.append(f"Suspicious use of '{keyword}'")
        
        for keyword in suspicious_keywords:
            if keyword in full_url:
                risk_score += 15
                risk_factors.append(f"Contains suspicious word '{keyword}'")
        
        # Domain analysis
        if len(domain.split('.')) > 3:  # Many subdomains
            risk_score += 25
            risk_factors.append("Multiple subdomains")
        
        if '-' in domain:
            risk_score += 10
            risk_factors.append("Hyphens in domain")
        
        if any(char.isdigit() for char in domain.replace('.', '')):
            risk_score += 15
            risk_factors.append("Numbers in domain")
        
        # URL length and complexity
        if len(url) > 100:
            risk_score += 10
            risk_factors.append("Very long URL")
        
        # Suspicious patterns
        if re.search(r'\d+\.\d+\.\d+\.\d+', domain):  # IP address
            risk_score += 30
            risk_factors.append("IP address instead of domain")
        
        if domain.count('.') > 4:
            risk_score += 20
            risk_factors.append("Excessive subdomain levels")
        
        # Typosquatting patterns
        common_typos = ['payp4l', 'g00gle', 'microsft', 'amazom']
        for typo in common_typos:
            if typo in domain:
                risk_score += 50
                risk_factors.append(f"Potential typosquatting: {typo}")
        
        # URL shorteners (medium risk)
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'short.link']
        if any(shortener in domain for shortener in shorteners):
            risk_score += 20
            risk_factors.append("URL shortener detected")
        
        # Cap the score
        risk_score = min(risk_score, 100)
        
        # Classification logic
        if risk_score >= 70:
            classification = "phishing"
            risk_level = "high"
        elif risk_score >= 40:
            classification = "suspicious"
            risk_level = "medium"
        else:
            classification = "legitimate"
            risk_level = "low"
        
        explanation = f"Heuristic analysis: {risk_score}% risk. " + "; ".join(risk_factors[:3])
        if len(risk_factors) > 3:
            explanation += f" (+{len(risk_factors)-3} other factors)"
        
        return {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'domain': domain,
            'deep_learning_probability': min(risk_score / 100, 1.0),
            'heuristic_score': risk_score,
            'api_score': 0,
            'final_score': risk_score,
            'classification': classification,
            'risk_level': risk_level,
            'explanation': explanation,
            'detailed_analysis': {
                'risk_factors': risk_factors,
                'domain_analysis': {'length': len(domain), 'subdomains': len(domain.split('.')) - 1},
                'url_length': len(url)
            }
        }

# Enhanced feedback validation system
class FeedbackValidator:
    @staticmethod
    def validate_feedback(feedback_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate user feedback before adding to dataset
        Returns validation result with approval status
        """
        validation_result = {
            'is_valid': True,
            'confidence_score': 0,
            'validation_notes': [],
            'auto_approve': False
        }
        
        # Check user confidence level
        confidence = feedback_data.get('confidence_level') or 3
        validation_result['confidence_score'] += confidence * 20
        
        # Check user expertise
        expertise = feedback_data.get('user_expertise') or 'beginner'
        expertise_weights = {'expert': 40, 'intermediate': 25, 'beginner': 10}
        validation_result['confidence_score'] += expertise_weights.get(expertise, 10)
        
        # Validate URL format
        url = feedback_data.get('url', '')
        if not url or len(url) < 10:
            validation_result['is_valid'] = False
            validation_result['validation_notes'].append('Invalid URL format')
        
        # Check for spam patterns in comments
        comment = feedback_data.get('user_comment', '')
        spam_indicators = ['buy now', 'click here', 'free money', 'urgent']
        if any(indicator in comment.lower() for indicator in spam_indicators):
            validation_result['confidence_score'] -= 30
            validation_result['validation_notes'].append('Potential spam content detected')
        
        # Auto-approve high confidence feedback
        if validation_result['confidence_score'] >= 80 and validation_result['is_valid']:
            validation_result['auto_approve'] = True
        
        return validation_result

# API Endpoints
@app.post("/api/scan-url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Scan a URL for phishing indicators"""
    start_time = datetime.now()
    
    try:
        engine = get_detection_engine()
        result = engine.analyze_url(request.url)
        
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Log the scan (simplified for serverless)
        log_scan_request(request.url, result)
        
        response = URLScanResponse(
            success=True,
            timestamp=result['timestamp'],
            url=result['url'],
            domain=result['domain'],
            deep_learning_probability=result['deep_learning_probability'],
            heuristic_score=result['heuristic_score'],
            api_score=result['api_score'],
            final_score=result['final_score'],
            classification=result['classification'],
            risk_level=result['risk_level'],
            explanation=result['explanation'],
            processing_time_ms=processing_time,
            detailed_analysis=result.get('detailed_analysis')
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error scanning URL {request.url}: {e}")
        raise HTTPException(status_code=500, detail=f"Error analyzing URL: {str(e)}")

@app.post("/api/feedback", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest):
    """Submit user feedback with validation"""
    try:
        feedback_id = f"fb_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        
        # Prepare feedback data
        feedback_data = {
            'feedback_id': feedback_id,
            'timestamp': datetime.now().isoformat(),
            'url': request.url,
            'correct_label': request.correct_label,
            'user_comment': request.user_comment,
            'confidence_level': request.confidence_level,
            'user_expertise': request.user_expertise
        }
        
        # Validate feedback
        validator = FeedbackValidator()
        validation_result = validator.validate_feedback(feedback_data)
        
        # Determine validation status
        if not validation_result['is_valid']:
            validation_status = 'rejected'
            message = f"Feedback rejected: {', '.join(validation_result['validation_notes'])}"
        elif validation_result['auto_approve']:
            validation_status = 'approved'
            message = "Feedback validated and approved automatically"
            # Add to dataset immediately
            await process_approved_feedback(feedback_data)
        else:
            validation_status = 'pending'
            message = "Feedback received and pending manual review"
        
        # Add validation info to feedback
        feedback_data.update({
            'validation_status': validation_status,
            'confidence_score': validation_result['confidence_score'],
            'validation_notes': validation_result['validation_notes']
        })
        
        # Save feedback with validation info
        save_feedback_with_validation(feedback_data)
        
        response = FeedbackResponse(
            success=True,
            message=message,
            feedback_id=feedback_id,
            validation_status=validation_status
        )
        
        logger.info(f"Feedback processed: {feedback_id} - Status: {validation_status}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing feedback: {str(e)}")

@app.get("/api/health")
async def health_check():
    """Health check endpoint - simplified for serverless"""
    try:
        engine = get_detection_engine()
        engine_type = type(engine).__name__
        return {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": "2.1.0",
            "build": "2026-02-28",
            "components": {
                "api": "operational",
                "detection_engine": engine_type,
                "engine_source": _engine_source,
                "admin_router": "loaded" if admin_router else "not_loaded",
                "environment": "serverless"
            }
        }
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return {
            "status": "degraded",
            "timestamp": datetime.now().isoformat(),
            "version": "2.1.0",
            "error": str(e)
        }

@app.get("/api/feedback/pending")
async def get_pending_feedback():
    """Get feedback pending manual review (admin endpoint) - serverless compatible"""
    try:
        # In serverless environment, return empty list
        # In production, this would query a database
        logger.info("Pending feedback requested")
        
        return {'success': True, 'pending_count': 0, 'feedback': []}
        
    except Exception as e:
        logger.error(f"Error getting pending feedback: {e}")
        return {'success': False, 'error': str(e)}

@app.post("/api/feedback/{feedback_id}/approve")
async def approve_feedback(feedback_id: str):
    """Approve pending feedback (admin endpoint) - serverless compatible"""
    try:
        # In serverless environment, just log the approval
        # In production, this would update a database
        logger.info(f"Feedback {feedback_id} approved")
        
        return {'success': True, 'message': 'Feedback approved (serverless mode)'}
        
    except Exception as e:
        logger.error(f"Error approving feedback: {e}")
        return {'success': False, 'error': str(e)}

# Helper functions
def log_scan_request(url: str, result: Dict[str, Any]):
    """Log scan request (simplified for serverless)"""
    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'classification': result['classification'],
            'final_score': result['final_score']
        }
        
        # In serverless, you might want to log to external service
        logger.info(f"Scan logged: {log_entry}")
        
    except Exception as e:
        logger.error(f"Error logging scan request: {e}")

def save_feedback_with_validation(feedback_data: Dict[str, Any]):
    """Save feedback with validation information - serverless compatible"""
    try:
        # In serverless environment, log instead of saving to file
        logger.info(f"Feedback received: {feedback_data}")
        
        # You can implement external storage here (database, cloud storage, etc.)
        # For now, just log the feedback
        
    except Exception as e:
        logger.error(f"Error processing feedback: {e}")

async def process_approved_feedback(feedback_data: Dict[str, Any]):
    """Process approved feedback and add to training dataset - serverless compatible"""
    try:
        # In serverless environment, just log the feedback
        # In production, this would save to a database
        logger.info(f"Processing approved feedback: {feedback_data.get('feedback_id', 'unknown')}")
        logger.info(f"URL: {feedback_data.get('url')}, Label: {feedback_data.get('correct_label')}")
        
    except Exception as e:
        logger.error(f"Error processing approved feedback: {e}")

# Exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal server error", "detail": str(exc)}
    )

# Vercel serverless deployment
# Vercel's @vercel/python runtime auto-detects the FastAPI `app` variable as ASGI
# No additional handler wrapper needed
logger.info("FastAPI app ready for Vercel serverless deployment")