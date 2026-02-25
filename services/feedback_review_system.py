"""
Feedback Review System for Phishing URL Detection
Purpose: Multi-stage feedback validation with admin review capabilities
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import pandas as pd
from enum import Enum
import uuid
import logging

logger = logging.getLogger(__name__)

class FeedbackStatus(Enum):
    """Feedback review status"""
    PENDING = "pending"           # Awaiting review
    APPROVED = "approved"         # Approved by admin
    REJECTED = "rejected"         # Rejected by admin  
    AUTO_APPROVED = "auto_approved"  # Passed automated validation
    FLAGGED = "flagged"          # Flagged for special attention

class FeedbackReviewSystem:
    """Enhanced feedback system with review capabilities"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.pending_file = os.path.join(data_dir, "pending_feedback.json")
        self.reviewed_file = os.path.join(data_dir, "reviewed_feedback.json") 
        self.rejected_file = os.path.join(data_dir, "rejected_feedback.json")
        self.admin_decisions_file = os.path.join(data_dir, "admin_decisions.json")
        self.quality_metrics_file = os.path.join(data_dir, "quality_metrics.json")
        
        # Ensure data directory exists
        os.makedirs(data_dir, exist_ok=True)
        
    def submit_user_feedback(self, 
                           url: str, 
                           correct_label: int, 
                           user_comment: Optional[str] = None,
                           confidence_level: Optional[int] = None,
                           user_expertise: Optional[str] = None,
                           user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Submit user feedback for review
        
        Args:
            url: The URL being reported
            correct_label: 0 (legitimate) or 1 (phishing)
            user_comment: User's explanation
            confidence_level: User's confidence (1-5)
            user_expertise: User's expertise level
            user_id: Optional user identifier
            
        Returns:
            Dict with feedback_id and status
        """
        
        feedback_id = f"fb_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
        
        feedback_data = {
            "feedback_id": feedback_id,
            "timestamp": datetime.now().isoformat(),
            "url": url,
            "correct_label": correct_label,
            "user_comment": user_comment,
            "confidence_level": confidence_level,
            "user_expertise": user_expertise,
            "user_id": user_id,
            "status": FeedbackStatus.PENDING.value,
            "auto_validation_result": None,
            "flagged_reasons": []
        }
        
        # Run automated validation
        auto_result = self._run_automated_validation(feedback_data)
        feedback_data.update(auto_result)
        
        # Save to pending feedback
        self._save_pending_feedback(feedback_data)
        
        # Log submission
        self._log_feedback_submission(feedback_data)
        
        return {
            "feedback_id": feedback_id,
            "status": feedback_data["status"],
            "message": self._get_status_message(feedback_data["status"])
        }
    
    def _run_automated_validation(self, feedback_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Automated validation to pre-screen feedback
        """
        flags = []
        validation_score = 0
        auto_decision = None
        
        # 1. URL Format Validation
        url = feedback_data["url"]
        if not self._is_valid_url(url):
            flags.append("invalid_url_format")
        
        # 2. Check against known patterns
        if self._check_suspicious_patterns(feedback_data):
            flags.append("suspicious_pattern")
            
        # 3. Confidence level check
        confidence = feedback_data.get("confidence_level", 3)
        if confidence and confidence >= 4:
            validation_score += 2
        elif confidence and confidence <= 2:
            flags.append("low_confidence")
            
        # 4. User expertise consideration
        expertise = feedback_data.get("user_expertise") or ""
        expertise = expertise.lower() if expertise else ""
        if expertise == "expert":
            validation_score += 3
        elif expertise == "beginner":
            validation_score -= 1
            
        # 5. Comment quality check
        comment = feedback_data.get("user_comment", "")
        if comment and len(comment) > 20:
            validation_score += 1
        elif not comment:
            flags.append("no_explanation")
            
        # 6. Check for contradictions
        if self._check_contradictions(feedback_data):
            flags.append("contradictory_feedback")
        
        # Decision logic
        status = FeedbackStatus.PENDING.value
        
        if validation_score >= 5 and len(flags) == 0:
            status = FeedbackStatus.AUTO_APPROVED.value
            auto_decision = "auto_approved"
        elif len(flags) > 2 or "suspicious_pattern" in flags:
            status = FeedbackStatus.FLAGGED.value
        
        return {
            "auto_validation_result": {
                "validation_score": validation_score,
                "flags": flags,
                "decision": auto_decision
            },
            "status": status,
            "flagged_reasons": flags
        }
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    def _check_suspicious_patterns(self, feedback_data: Dict[str, Any]) -> bool:
        """Check for suspicious feedback patterns"""
        # Check for obvious spam patterns
        comment = feedback_data.get("user_comment") or ""
        comment = comment.lower() if comment else ""
        
        spam_keywords = ["spam", "click here", "free", "money", "win", "congratulations"]
        if any(keyword in comment for keyword in spam_keywords):
            return True
            
        # Check for extremely short or generic comments
        if comment and len(comment) < 5:
            return True
            
        return False
    
    def _check_contradictions(self, feedback_data: Dict[str, Any]) -> bool:
        """Check for contradictory feedback patterns"""
        # This could be enhanced with ML-based contradiction detection
        # For now, check basic patterns
        
        url = feedback_data.get("url") or ""
        url = url.lower() if url else ""
        label = feedback_data["correct_label"]
        comment = feedback_data.get("user_comment") or ""
        comment = comment.lower() if comment else ""
        
        # Check if legitimate sites are being marked as phishing without good reason
        trusted_domains = ["google.com", "github.com", "microsoft.com", "apple.com"]
        if label == 1 and any(domain in url for domain in trusted_domains):
            if not any(word in comment for word in ["fake", "spoof", "suspicious"]):
                return True
                
        return False
    
    def get_pending_feedback(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get feedback awaiting review"""
        try:
            if os.path.exists(self.pending_file):
                with open(self.pending_file, 'r') as f:
                    all_feedback = json.load(f)
                
                # Filter pending and flagged items
                pending = [f for f in all_feedback 
                          if f.get("status") in [FeedbackStatus.PENDING.value, FeedbackStatus.FLAGGED.value]]
                
                # Sort by timestamp (oldest first) and flagged items first
                pending.sort(key=lambda x: (
                    0 if x.get("status") == FeedbackStatus.FLAGGED.value else 1,
                    x.get("timestamp", "")
                ))
                
                return pending[:limit]
            return []
        except Exception as e:
            logger.error(f"Error loading pending feedback: {e}")
            return []
    
    def admin_review_feedback(self, 
                            feedback_id: str, 
                            admin_decision: str,  # "approve" or "reject"
                            admin_comment: str = "",
                            admin_id: str = "admin") -> Dict[str, Any]:
        """
        Admin reviews and decides on feedback
        """
        try:
            # Load pending feedback
            pending_feedback = self._load_json_file(self.pending_file, [])
            feedback_item = None
            
            # Find the feedback item
            for i, item in enumerate(pending_feedback):
                if item["feedback_id"] == feedback_id:
                    feedback_item = pending_feedback.pop(i)
                    break
                    
            if not feedback_item:
                return {"success": False, "message": "Feedback not found"}
            
            # Update status
            decision_timestamp = datetime.now().isoformat()
            
            if admin_decision and admin_decision.lower() == "approve":
                feedback_item["status"] = FeedbackStatus.APPROVED.value
                # Add to training dataset
                self._add_to_training_dataset(feedback_item)
                # Save to reviewed feedback
                self._save_reviewed_feedback(feedback_item)
                
            elif admin_decision and admin_decision.lower() == "reject":
                feedback_item["status"] = FeedbackStatus.REJECTED.value
                feedback_item["rejection_reason"] = admin_comment
                # Save to rejected feedback
                self._save_rejected_feedback(feedback_item)
            
            # Log admin decision
            admin_decision_log = {
                "decision_id": str(uuid.uuid4()),
                "feedback_id": feedback_id,
                "admin_id": admin_id,
                "decision": admin_decision,
                "admin_comment": admin_comment,
                "timestamp": decision_timestamp,
                "original_feedback": feedback_item
            }
            self._log_admin_decision(admin_decision_log)
            
            # Update pending feedback file
            with open(self.pending_file, 'w') as f:
                json.dump(pending_feedback, f, indent=2)
            
            # Update quality metrics
            self._update_quality_metrics(admin_decision)
            
            return {
                "success": True,
                "message": f"Feedback {admin_decision}d successfully",
                "feedback_id": feedback_id
            }
            
        except Exception as e:
            logger.error(f"Error in admin review: {e}")
            return {"success": False, "message": str(e)}
    
    def get_admin_dashboard_data(self) -> Dict[str, Any]:
        """Get data for admin dashboard"""
        try:
            pending_count = len(self.get_pending_feedback())
            flagged_count = len([f for f in self.get_pending_feedback() 
                               if f.get("status") == FeedbackStatus.FLAGGED.value])
            
            # Get recent admin decisions
            admin_decisions = self._load_json_file(self.admin_decisions_file, [])
            recent_decisions = sorted(admin_decisions, 
                                    key=lambda x: x.get("timestamp", ""), 
                                    reverse=True)[:10]
            
            # Get quality metrics
            quality_metrics = self._load_json_file(self.quality_metrics_file, {})
            
            return {
                "pending_count": pending_count,
                "flagged_count": flagged_count,
                "recent_decisions": recent_decisions,
                "quality_metrics": quality_metrics,
                "system_health": self._get_system_health()
            }
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {"error": str(e)}
    
    def _save_pending_feedback(self, feedback_data: Dict[str, Any]):
        """Save feedback to pending file"""
        pending_feedback = self._load_json_file(self.pending_file, [])
        pending_feedback.append(feedback_data)
        
        with open(self.pending_file, 'w') as f:
            json.dump(pending_feedback, f, indent=2)
    
    def _save_reviewed_feedback(self, feedback_data: Dict[str, Any]):
        """Save reviewed feedback"""
        reviewed_feedback = self._load_json_file(self.reviewed_file, [])
        reviewed_feedback.append(feedback_data)
        
        with open(self.reviewed_file, 'w') as f:
            json.dump(reviewed_feedback, f, indent=2)
    
    def _save_rejected_feedback(self, feedback_data: Dict[str, Any]):
        """Save rejected feedback"""
        rejected_feedback = self._load_json_file(self.rejected_file, [])
        rejected_feedback.append(feedback_data)
        
        with open(self.rejected_file, 'w') as f:
            json.dump(rejected_feedback, f, indent=2)
    
    def _add_to_training_dataset(self, feedback_data: Dict[str, Any]):
        """Add approved feedback to training dataset"""
        try:
            dataset_file = os.path.join(self.data_dir, "approved_feedback_dataset.csv")
            
            new_entry = {
                'url': feedback_data['url'],
                'label': feedback_data['correct_label'],
                'source': 'user_feedback',
                'feedback_id': feedback_data['feedback_id'],
                'timestamp': feedback_data['timestamp']
            }
            
            if os.path.exists(dataset_file):
                df = pd.read_csv(dataset_file)
            else:
                df = pd.DataFrame(columns=['url', 'label', 'source', 'feedback_id', 'timestamp'])
            
            df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
            df = df.drop_duplicates(subset=['url'], keep='last')
            df.to_csv(dataset_file, index=False)
            
            logger.info(f"Added feedback to training dataset: {feedback_data['feedback_id']}")
            
        except Exception as e:
            logger.error(f"Error adding to training dataset: {e}")
    
    def _log_feedback_submission(self, feedback_data: Dict[str, Any]):
        """Log feedback submission"""
        logger.info(f"Feedback submitted: {feedback_data['feedback_id']} - Status: {feedback_data['status']}")
    
    def _log_admin_decision(self, decision_data: Dict[str, Any]):
        """Log admin decision"""
        decisions = self._load_json_file(self.admin_decisions_file, [])
        decisions.append(decision_data)
        
        with open(self.admin_decisions_file, 'w') as f:
            json.dump(decisions, f, indent=2)
    
    def _update_quality_metrics(self, decision: str):
        """Update quality metrics"""
        metrics = self._load_json_file(self.quality_metrics_file, {
            "total_reviewed": 0,
            "approved": 0,
            "rejected": 0,
            "approval_rate": 0.0
        })
        
        metrics["total_reviewed"] += 1
        if decision and decision.lower() == "approve":
            metrics["approved"] += 1
        else:
            metrics["rejected"] += 1
            
        metrics["approval_rate"] = metrics["approved"] / metrics["total_reviewed"] * 100
        
        with open(self.quality_metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
    
    def _get_system_health(self) -> Dict[str, Any]:
        """Get system health metrics"""
        return {
            "status": "healthy",
            "last_check": datetime.now().isoformat(),
            "pending_queue_size": len(self.get_pending_feedback()),
            "files_status": {
                "pending": os.path.exists(self.pending_file),
                "reviewed": os.path.exists(self.reviewed_file),
                "rejected": os.path.exists(self.rejected_file)
            }
        }
    
    def _get_status_message(self, status: str) -> str:
        """Get human-readable status message"""
        messages = {
            FeedbackStatus.PENDING.value: "Thank you! Your feedback is pending admin review.",
            FeedbackStatus.AUTO_APPROVED.value: "Thank you! Your feedback has been automatically approved.",
            FeedbackStatus.FLAGGED.value: "Thank you! Your feedback has been flagged for detailed review.",
        }
        return messages.get(status, "Feedback received.")
    
    def _load_json_file(self, filepath: str, default: Any = None) -> Any:
        """Safely load JSON file"""
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    return json.load(f)
            return default if default is not None else []
        except Exception as e:
            logger.error(f"Error loading {filepath}: {e}")
            return default if default is not None else []