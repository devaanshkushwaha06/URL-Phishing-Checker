"""
FastAPI Backend for Phishing URL Detection System
Purpose: RESTful API with real-time detection and feedback learning
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import uvicorn
import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd
from services.detection_engine import HybridDetectionEngine
import asyncio
import threading

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AI Phishing Detection API",
    description="Hybrid deep learning + heuristic phishing URL detection system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global detection engine
detection_engine = None

# Pydantic models for request/response
class URLScanRequest(BaseModel):
    """Request model for URL scanning"""
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('URL cannot be empty')
        
        # Basic URL validation
        v = v.strip()
        if not (v.startswith('http://') or v.startswith('https://') or v.startswith('ftp://')):
            # Add https:// if no protocol specified
            v = 'https://' + v
        
        if len(v) > 2000:
            raise ValueError('URL too long (max 2000 characters)')
            
        return v

class URLScanResponse(BaseModel):
    """Response model for URL scanning results"""
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
    """Request model for user feedback"""
    url: str
    correct_label: int  # 0 = legitimate, 1 = phishing
    user_comment: Optional[str] = None
    confidence_level: Optional[int] = None  # 1-5 rating for validation
    user_expertise: Optional[str] = None    # beginner, intermediate, expert
    
    @validator('correct_label')
    def validate_label(cls, v):
        if v not in [0, 1]:
            raise ValueError('correct_label must be 0 (legitimate) or 1 (phishing)')
        return v
    
    @validator('confidence_level')
    def validate_confidence(cls, v):
        if v is not None and (v < 1 or v > 5):
            raise ValueError('confidence_level must be between 1 and 5')
        return v

class FeedbackResponse(BaseModel):
    """Response model for feedback submission"""
    success: bool
    message: str
    feedback_id: str
    validation_status: str  # pending, approved, rejected

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str
    components: Dict[str, str]

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
        confidence = feedback_data.get('confidence_level', 3)
        validation_result['confidence_score'] += confidence * 20
        
        # Check user expertise
        expertise = feedback_data.get('user_expertise', 'beginner')
        expertise_weights = {'expert': 40, 'intermediate': 25, 'beginner': 10}
        validation_result['confidence_score'] += expertise_weights.get(expertise, 10)
        
        # Validate URL format
        url = feedback_data.get('url', '')
        if not url or len(url) < 10:
            validation_result['is_valid'] = False
            validation_result['validation_notes'].append('Invalid URL format')
        
        # Check for spam patterns in comments
        comment = feedback_data.get('user_comment', '')
        spam_indicators = ['buy now', 'click here', 'free money', 'urgent', 'limited time']
        if any(indicator in comment.lower() for indicator in spam_indicators):
            validation_result['confidence_score'] -= 30
            validation_result['validation_notes'].append('Potential spam content detected')
        
        # Check for suspicious patterns
        if comment and len(comment) > 500:
            validation_result['validation_notes'].append('Comment too long')
        
        # Validate against known good/bad patterns
        if 'phishing' in url.lower() and feedback_data.get('correct_label') == 0:
            validation_result['confidence_score'] -= 20
            validation_result['validation_notes'].append('Label conflicts with URL pattern')
        
        # Auto-approve high confidence feedback
        if validation_result['confidence_score'] >= 80 and validation_result['is_valid']:
            validation_result['auto_approve'] = True
        
        return validation_result

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize the detection engine on startup"""
    global detection_engine
    
    logger.info("🚀 Starting Phishing Detection API...")
    
    # Initialize detection engine
    virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
    detection_engine = HybridDetectionEngine(virustotal_key)
    
    # Create necessary directories
    os.makedirs('logs', exist_ok=True)
    os.makedirs('data', exist_ok=True)
    
    logger.info("✅ Detection engine initialized successfully")

# Main endpoints
@app.post("/scan-url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """
    Scan a URL for phishing indicators
    
    Returns comprehensive analysis with risk score and classification
    """
    start_time = datetime.now()
    
    try:
        if detection_engine is None:
            raise HTTPException(status_code=503, detail="Detection engine not initialized")
        
        # Perform URL analysis
        result = detection_engine.analyze_url(request.url)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds() * 1000
        
        # Log the scan
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
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing URL: {str(e)}"
        )

@app.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest, background_tasks: BackgroundTasks):
    """
    Submit user feedback with validation for model improvement
    
    Validates feedback before adding to dataset and triggers background retraining
    """
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
            # Schedule immediate processing for high-confidence feedback
            background_tasks.add_task(process_approved_feedback_task, feedback_data)
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
        
        # Only process if approved
        if validation_status == 'approved':
            background_tasks.add_task(process_feedback_retraining, feedback_data)
        
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
        raise HTTPException(
            status_code=500,
            detail=f"Error processing feedback: {str(e)}"
        )

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint
    
    Returns system status and component availability
    """
    try:
        components = {}
        
        # Check detection engine
        if detection_engine:
            components['detection_engine'] = 'operational'
            components['ml_model'] = 'loaded' if detection_engine.ml_predictor.model else 'not_loaded'
            components['virustotal_api'] = 'available' if detection_engine.virustotal_api.is_available() else 'unavailable'
        else:
            components['detection_engine'] = 'not_initialized'
        
        # Check data directories
        components['data_directory'] = 'exists' if os.path.exists('data') else 'missing'
        components['models_directory'] = 'exists' if os.path.exists('models') else 'missing'
        
        response = HealthResponse(
            status="healthy",
            timestamp=datetime.now().isoformat(),
            version="1.0.0",
            components=components
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Health check error: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.get("/stats")
async def get_statistics():
    """Get system usage statistics"""
    try:
        stats = {
            'total_scans': get_scan_count(),
            'total_feedback': get_feedback_count(),
            'validated_feedback': get_validated_feedback_count(),
            'pending_feedback': get_pending_feedback_count(),
            'uptime': get_uptime(),
            'last_model_update': get_last_model_update()
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return {"error": str(e)}

@app.get("/feedback/pending")
async def get_pending_feedback():
    """Get feedback pending manual review (admin endpoint)"""
    try:
        validation_file = 'data/feedback_with_validation.json'
        
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                all_feedback = json.load(f)
            
            # Filter pending feedback
            pending_feedback = [fb for fb in all_feedback if fb.get('validation_status') == 'pending']
            
            return {
                'success': True,
                'pending_count': len(pending_feedback),
                'feedback': pending_feedback
            }
        
        return {'success': True, 'pending_count': 0, 'feedback': []}
        
    except Exception as e:
        logger.error(f"Error getting pending feedback: {e}")
        return {'success': False, 'error': str(e)}

@app.post("/feedback/{feedback_id}/approve")
async def approve_feedback(feedback_id: str, background_tasks: BackgroundTasks):
    """Approve pending feedback (admin endpoint)"""
    try:
        validation_file = 'data/feedback_with_validation.json'
        
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                all_feedback = json.load(f)
            
            # Find and approve feedback
            for feedback in all_feedback:
                if feedback.get('feedback_id') == feedback_id:
                    feedback['validation_status'] = 'approved'
                    feedback['approved_timestamp'] = datetime.now().isoformat()
                    
                    # Save updated feedback
                    with open(validation_file, 'w') as f:
                        json.dump(all_feedback, f, indent=2)
                    
                    # Process the approved feedback
                    background_tasks.add_task(process_approved_feedback_task, feedback)
                    background_tasks.add_task(process_feedback_retraining, feedback)
                    
                    return {'success': True, 'message': 'Feedback approved and added to dataset'}
            
            return {'success': False, 'message': 'Feedback not found'}
        
        return {'success': False, 'message': 'No feedback data found'}
        
    except Exception as e:
        logger.error(f"Error approving feedback: {e}")
        return {'success': False, 'error': str(e)}

@app.post("/feedback/{feedback_id}/reject")
async def reject_feedback(feedback_id: str, rejection_reason: Optional[str] = None):
    """Reject pending feedback (admin endpoint)"""
    try:
        validation_file = 'data/feedback_with_validation.json'
        
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                all_feedback = json.load(f)
            
            # Find and reject feedback
            for feedback in all_feedback:
                if feedback.get('feedback_id') == feedback_id:
                    feedback['validation_status'] = 'rejected'
                    feedback['rejected_timestamp'] = datetime.now().isoformat()
                    if rejection_reason:
                        feedback['rejection_reason'] = rejection_reason
                    
                    # Save updated feedback
                    with open(validation_file, 'w') as f:
                        json.dump(all_feedback, f, indent=2)
                    
                    return {'success': True, 'message': 'Feedback rejected'}
            
            return {'success': False, 'message': 'Feedback not found'}
        
        return {'success': False, 'message': 'No feedback data found'}
        
    except Exception as e:
        logger.error(f"Error rejecting feedback: {e}")
        return {'success': False, 'error': str(e)}

# Helper functions
def log_scan_request(url: str, result: Dict[str, Any]):
    """Log scan request for analytics"""
    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'classification': result['classification'],
            'final_score': result['final_score']
        }
        
        log_file = 'logs/scan_requests.json'
        
        # Append to log file
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(log_entry)
        
        # Keep only last 1000 entries
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(log_file, 'w') as f:
            json.dump(logs, f)
            
    except Exception as e:
        logger.error(f"Error logging scan request: {e}")

def save_feedback_with_validation(feedback_data: Dict[str, Any]):
    """Save feedback with validation information"""
    try:
        # Save to validation feedback file
        validation_file = 'data/feedback_with_validation.json'
        
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                feedback_list = json.load(f)
        else:
            feedback_list = []
        
        feedback_list.append(feedback_data)
        
        with open(validation_file, 'w') as f:
            json.dump(feedback_list, f, indent=2)
        
        # Also save to original feedback file for compatibility
        save_feedback(feedback_data)
        
    except Exception as e:
        logger.error(f"Error saving feedback with validation: {e}")

async def process_approved_feedback_task(feedback_data: Dict[str, Any]):
    """Process approved feedback and add to validated dataset"""
    try:
        dataset_file = 'data/validated_dataset.csv'
        
        new_entry = {
            'url': feedback_data['url'],
            'label': feedback_data['correct_label'],
            'validation_score': feedback_data.get('confidence_score', 0),
            'timestamp': feedback_data['timestamp'],
            'feedback_id': feedback_data['feedback_id']
        }
        
        # Load existing dataset or create new
        if os.path.exists(dataset_file):
            df = pd.read_csv(dataset_file)
        else:
            df = pd.DataFrame(columns=['url', 'label', 'validation_score', 'timestamp', 'feedback_id'])
        
        # Add new entry
        df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
        
        # Remove duplicates (keep highest validation score)
        df = df.sort_values('validation_score', ascending=False)
        df = df.drop_duplicates(subset=['url'], keep='first')
        
        # Save updated dataset
        df.to_csv(dataset_file, index=False)
        
        logger.info(f"Added validated feedback to training dataset: {feedback_data['feedback_id']}")
        
    except Exception as e:
        logger.error(f"Error processing approved feedback: {e}")

def save_feedback(feedback_data: Dict[str, Any]):
    """Save user feedback to file"""
    try:
        feedback_file = 'data/feedback.json'
        
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                feedback_list = json.load(f)
        else:
            feedback_list = []
        
        feedback_list.append(feedback_data)
        
        with open(feedback_file, 'w') as f:
            json.dump(feedback_list, f, indent=2)
        
        # Also update training dataset
        update_training_dataset(feedback_data)
        
    except Exception as e:
        logger.error(f"Error saving feedback: {e}")

def update_training_dataset(feedback_data: Dict[str, Any]):
    """Update training dataset with feedback"""
    try:
        dataset_file = 'data/feedback_dataset.csv'
        
        # Create new entry
        new_entry = {
            'url': feedback_data['url'],
            'label': feedback_data['correct_label']
        }
        
        # Load existing dataset or create new
        if os.path.exists(dataset_file):
            df = pd.read_csv(dataset_file)
        else:
            df = pd.DataFrame(columns=['url', 'label'])
        
        # Add new entry
        df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
        
        # Remove duplicates (keep latest)
        df = df.drop_duplicates(subset=['url'], keep='last')
        
        # Save updated dataset
        df.to_csv(dataset_file, index=False)
        
        logger.info(f"Updated feedback dataset with {len(df)} entries")
        
    except Exception as e:
        logger.error(f"Error updating training dataset: {e}")

async def process_feedback_retraining(feedback_data: Dict[str, Any]):
    """Background task for model retraining"""
    try:
        logger.info("🔄 Starting background model retraining...")
        
        # Check if we have enough feedback for retraining
        feedback_file = 'data/feedback.json'
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                feedback_list = json.load(f)
            
            # Retrain every 50 feedback entries
            if len(feedback_list) % 50 == 0:
                logger.info(f"Triggering model retraining with {len(feedback_list)} feedback entries")
                
                # Run retraining in a separate thread to avoid blocking
                def retrain_model():
                    try:
                        from models.train_model import PhishingModelTrainer
                        
                        # Combine original dataset with feedback
                        original_dataset = 'data/generated_dataset.csv'
                        feedback_dataset = 'data/feedback_dataset.csv'
                        
                        if os.path.exists(original_dataset) and os.path.exists(feedback_dataset):
                            # Load both datasets
                            df_original = pd.read_csv(original_dataset)
                            df_feedback = pd.read_csv(feedback_dataset)
                            
                            # Combine datasets
                            df_combined = pd.concat([df_original, df_feedback], ignore_index=True)
                            
                            # Save combined dataset
                            combined_file = 'data/combined_training_dataset.csv'
                            df_combined.to_csv(combined_file, index=False)
                            
                            # Retrain model
                            trainer = PhishingModelTrainer()
                            trainer.train_model(combined_file, epochs=10)  # Quick retraining
                            trainer.save_model()
                            
                            logger.info("✅ Model retraining completed successfully")
                        
                    except Exception as e:
                        logger.error(f"Model retraining failed: {e}")
                
                # Run in background thread
                thread = threading.Thread(target=retrain_model)
                thread.daemon = True
                thread.start()
        
    except Exception as e:
        logger.error(f"Error in background retraining: {e}")

def get_scan_count() -> int:
    """Get total number of scans performed"""
    try:
        log_file = 'logs/scan_requests.json'
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
            return len(logs)
        return 0
    except:
        return 0

def get_feedback_count() -> int:
    """Get total feedback count"""
    try:
        feedback_file = 'data/feedback.json'
        if os.path.exists(feedback_file):
            with open(feedback_file, 'r') as f:
                feedback_list = json.load(f)
            return len(feedback_list)
        return 0
    except:
        return 0

def get_validated_feedback_count() -> int:
    """Get count of validated (approved) feedback"""
    try:
        validation_file = 'data/feedback_with_validation.json'
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                all_feedback = json.load(f)
            
            approved_count = len([fb for fb in all_feedback if fb.get('validation_status') == 'approved'])
            return approved_count
        return 0
    except:
        return 0

def get_pending_feedback_count() -> int:
    """Get count of pending feedback"""
    try:
        validation_file = 'data/feedback_with_validation.json'
        if os.path.exists(validation_file):
            with open(validation_file, 'r') as f:
                all_feedback = json.load(f)
            
            pending_count = len([fb for fb in all_feedback if fb.get('validation_status') == 'pending'])
            return pending_count
        return 0
    except:
        return 0

def get_uptime() -> str:
    """Get service uptime"""
    # Simplified uptime - in production, track actual startup time
    return "Service running"

def get_last_model_update() -> str:
    """Get last model update timestamp"""
    try:
        model_files = [f for f in os.listdir('models') if f.endswith('_metadata.json')]
        if model_files:
            latest_file = max(model_files, key=lambda x: os.path.getctime(os.path.join('models', x)))
            return os.path.getctime(os.path.join('models', latest_file))
        return "No model found"
    except:
        return "Unknown"

# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "error": "Internal server error", "detail": str(exc)}
    )

# Development server
def run_development_server():
    """Run development server"""
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    print("🌐 Starting AI Phishing Detection API Server")
    print("=" * 50)
    print("📍 Server will be available at: http://localhost:8000")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("=" * 50)
    
    run_development_server()