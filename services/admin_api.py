"""
Admin Review API Endpoints  
Purpose: REST API for admin feedback review functionality with secure authentication
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from services.feedback_review_system import FeedbackReviewSystem
from services.admin_auth import admin_auth

logger = logging.getLogger(__name__)

# Create router for admin endpoints
admin_router = APIRouter(prefix="/admin", tags=["admin"])

# Initialize review system
review_system = FeedbackReviewSystem()

# Pydantic models for admin API
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class AdminLoginResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    username: Optional[str] = None
    expires_in: Optional[int] = None
    error: Optional[str] = None

class AdminReviewRequest(BaseModel):
    feedback_id: str
    decision: str  # "approve" or "reject"
    admin_comment: Optional[str] = ""
    admin_id: Optional[str] = "admin"

class AdminReviewResponse(BaseModel):
    success: bool
    message: str
    feedback_id: str

class PendingFeedbackResponse(BaseModel):
    feedback_id: str
    timestamp: str
    url: str
    correct_label: int
    user_comment: Optional[str]
    confidence_level: Optional[int]
    user_expertise: Optional[str]  
    status: str
    flagged_reasons: List[str]
    auto_validation_result: Optional[Dict[str, Any]]

class DashboardResponse(BaseModel):
    pending_count: int
    flagged_count: int
    recent_decisions: List[Dict[str, Any]]
    quality_metrics: Dict[str, Any]
    system_health: Dict[str, Any]

# Authentication verification
async def verify_admin_token(authorization: str = Header(None)):
    """Verify admin authentication token"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.replace("Bearer ", "")
    
    # Validate token using auth service
    session_info = admin_auth.validate_token(token)
    if not session_info:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return session_info

# Authentication endpoints
@admin_router.post("/authenticate", response_model=AdminLoginResponse)
async def authenticate_admin(login_request: AdminLoginRequest):
    """
    Authenticate admin user and return session token
    """
    try:
        result = admin_auth.authenticate(login_request.username, login_request.password)
        
        return AdminLoginResponse(
            success=result['success'],
            token=result.get('token'),
            username=result.get('username') if result['success'] else None,
            expires_in=result.get('expires_in') if result['success'] else None,
            error=result.get('error') if not result['success'] else None
        )
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return AdminLoginResponse(
            success=False,
            error="Authentication service error"
        )

@admin_router.post("/logout")
async def logout_admin(authorization: str = Header(None)):
    """
    Logout admin and revoke session token
    """
    session_info = await verify_admin_token(authorization)
    
    try:
        token = authorization.replace("Bearer ", "")
        success = admin_auth.revoke_token(token)
        
        return {
            "success": success,
            "message": "Logged out successfully" if success else "Token not found"
        }
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout error")

@admin_router.get("/dashboard", response_model=DashboardResponse)
async def get_admin_dashboard(authorization: str = Header(None)):
    """
    Get admin dashboard data with pending feedback statistics
    """ 
    await verify_admin_token(authorization)
    
    try:
        dashboard_data = review_system.get_admin_dashboard_data()
        
        if "error" in dashboard_data:
            raise HTTPException(status_code=500, detail=dashboard_data["error"])
        
        return DashboardResponse(**dashboard_data)
        
    except Exception as e:
        logger.error(f"Error getting admin dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/pending-feedback")
async def get_pending_feedback(
    limit: int = 50,
    authorization: str = Header(None)
) -> List[PendingFeedbackResponse]:
    """
    Get list of feedback items pending review
    """
    await verify_admin_token(authorization)
    
    try:
        pending_items = review_system.get_pending_feedback(limit)
        
        return [PendingFeedbackResponse(**item) for item in pending_items]
        
    except Exception as e:
        logger.error(f"Error getting pending feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.post("/review-feedback", response_model=AdminReviewResponse)
async def review_feedback(
    review_request: AdminReviewRequest,
    authorization: str = Header(None)
):
    """
    Admin reviews and approves/rejects feedback
    """
    await verify_admin_token(authorization)
    
    try:
        if review_request.decision.lower() not in ["approve", "reject"]:
            raise HTTPException(status_code=400, detail="Decision must be 'approve' or 'reject'")
        
        result = review_system.admin_review_feedback(
            feedback_id=review_request.feedback_id,
            admin_decision=review_request.decision,
            admin_comment=review_request.admin_comment,
            admin_id=review_request.admin_id
        )
        
        if not result["success"]:
            raise HTTPException(status_code=404, detail=result["message"])
        
        return AdminReviewResponse(**result)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reviewing feedback: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/feedback-stats")
async def get_feedback_statistics(authorization: str = Header(None)):
    """
    Get detailed feedback statistics
    """
    await verify_admin_token(authorization)
    
    try:
        dashboard_data = review_system.get_admin_dashboard_data()
        
        # Calculate additional statistics
        quality_metrics = dashboard_data.get("quality_metrics", {})
        
        stats = {
            "overview": {
                "pending_count": dashboard_data.get("pending_count", 0),
                "flagged_count": dashboard_data.get("flagged_count", 0),
                "total_reviewed": quality_metrics.get("total_reviewed", 0),
                "approval_rate": quality_metrics.get("approval_rate", 0.0)
            },
            "quality_metrics": quality_metrics,
            "system_health": dashboard_data.get("system_health", {}),
            "recent_activity": dashboard_data.get("recent_decisions", [])[:5],
            "security_stats": admin_auth.get_security_stats()
        }
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting feedback statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/debug")
async def debug_info(authorization: str = Header(None)):
    """
    Debug endpoint: shows everything in memory and /tmp files
    """
    await verify_admin_token(authorization)
    import os, tempfile
    from services.feedback_review_system import FeedbackReviewSystem
    
    tmp_dir = os.path.join(tempfile.gettempdir(), 'phishing_data')
    data_dir = review_system.data_dir
    
    def read_file(path):
        try:
            import json
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
            return f"FILE NOT FOUND: {path}"
        except Exception as e:
            return f"ERROR: {e}"
    
    return {
        "data_dir": data_dir,
        "memory_pending_count": len(FeedbackReviewSystem._memory_pending),
        "memory_pending": FeedbackReviewSystem._memory_pending,
        "memory_approved_count": len(FeedbackReviewSystem._memory_approved_dataset),
        "memory_approved": FeedbackReviewSystem._memory_approved_dataset,
        "memory_reviewed_count": len(FeedbackReviewSystem._memory_reviewed),
        "memory_rejected_count": len(FeedbackReviewSystem._memory_rejected),
        "memory_quality_metrics": FeedbackReviewSystem._memory_quality_metrics,
        "file_pending": read_file(review_system.pending_file),
        "file_reviewed": read_file(review_system.reviewed_file),
    }

@admin_router.get("/approved-dataset")
async def get_approved_dataset(authorization: str = Header(None)):
    """
    Get approved feedback entries (from memory + CSV file)
    """
    await verify_admin_token(authorization)
    
    try:
        from services.feedback_review_system import FeedbackReviewSystem
        import os, pandas as pd
        
        # Start with in-memory approved entries
        entries = list(FeedbackReviewSystem._memory_approved_dataset)
        
        # Also try reading from CSV file
        try:
            dataset_file = os.path.join(review_system.data_dir, "approved_feedback_dataset.csv")
            if os.path.exists(dataset_file):
                df = pd.read_csv(dataset_file)
                file_entries = df.to_dict(orient='records')
                existing_ids = {e.get('feedback_id') for e in entries}
                for fe in file_entries:
                    if fe.get('feedback_id') not in existing_ids:
                        entries.append(fe)
        except Exception as fe:
            logger.warning(f"Could not read dataset CSV: {fe}")
        
        return {"count": len(entries), "entries": entries}
    
    except Exception as e:
        logger.error(f"Error getting approved dataset: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@admin_router.get("/health")
async def admin_system_health(authorization: str = Header(None)):
    """
    Check admin system health
    """
    await verify_admin_token(authorization)
    
    try:
        health_data = review_system._get_system_health()
        health_data.update({
            "auth_service": "operational",
            "security_stats": admin_auth.get_security_stats()
        })
        return health_data
    except Exception as e:
        logger.error(f"Error checking admin system health: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Batch operations
@admin_router.post("/batch-review")  
async def batch_review_feedback(
    feedback_ids: List[str],
    decision: str,
    admin_comment: str = "",
    admin_id: str = "admin",
    authorization: str = Header(None)
):
    """
    Review multiple feedback items at once
    """
    await verify_admin_token(authorization)
    
    try:
        if decision.lower() not in ["approve", "reject"]:
            raise HTTPException(status_code=400, detail="Decision must be 'approve' or 'reject'")
        
        results = []
        
        for feedback_id in feedback_ids:
            result = review_system.admin_review_feedback(
                feedback_id=feedback_id,
                admin_decision=decision,
                admin_comment=admin_comment,
                admin_id=admin_id
            )
            results.append({
                "feedback_id": feedback_id,
                **result
            })
        
        successful = len([r for r in results if r.get("success", False)])
        
        return {
            "message": f"Processed {len(feedback_ids)} items. {successful} successful.",
            "results": results,
            "summary": {
                "total": len(feedback_ids),
                "successful": successful,
                "failed": len(feedback_ids) - successful
            }
        }
        
    except Exception as e:
        logger.error(f"Error in batch review: {e}")
        raise HTTPException(status_code=500, detail=str(e))