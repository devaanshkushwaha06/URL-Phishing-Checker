"""
Test Script for Feedback Review System
Purpose: Demonstrate the functionality of the new feedback review system
"""

import json
import requests
import time
from datetime import datetime

# Configuration
API_BASE_URL = 'http://localhost:8000'
ADMIN_TOKEN = 'admin_secret_token_123'

def test_feedback_submission():
    """Test submitting various types of feedback"""
    
    print("🧪 Testing Feedback Submission System")
    print("=" * 50)
    
    test_cases = [
        {
            "name": "High Quality Expert Feedback",
            "data": {
                "url": "http://paypa1-security.com/login",
                "correct_label": 1,
                "user_comment": "This URL uses character substitution (1 instead of l) to mimic PayPal's domain. Classic typosquatting attack.",
                "confidence_level": 5,
                "user_expertise": "expert",
                "user_id": "security_expert_001"
            }
        },
        {
            "name": "Beginner Feedback - Low Detail",
            "data": {
                "url": "https://www.google.com",
                "correct_label": 0,
                "user_comment": "looks ok",
                "confidence_level": 2,
                "user_expertise": "beginner",
                "user_id": "beginner_001"
            }
        },
        {
            "name": "Suspicious Feedback - Potential Spam",
            "data": {
                "url": "https://github.com",
                "correct_label": 1,
                "user_comment": "spam site click here for free money",
                "confidence_level": 1,
                "user_expertise": "beginner",
                "user_id": "suspicious_001"
            }
        },
        {
            "name": "Auto-Approval Candidate",
            "data": {
                "url": "https://amazon-security-alert.net/verify",
                "correct_label": 1,
                "user_comment": "Fake Amazon domain using subdomain to deceive users. The real Amazon domain is amazon.com, not amazon-security-alert.net",
                "confidence_level": 5,
                "user_expertise": "expert",
                "user_id": "cybersec_analyst"
            }
        },
        {
            "name": "Contradictory Feedback",
            "data": {
                "url": "https://www.microsoft.com",
                "correct_label": 1,
                "user_comment": "this is phishing",
                "confidence_level": 3,
                "user_expertise": "intermediate",
                "user_id": "confused_user"
            }
        }
    ]
    
    feedback_ids = []
    
    for test_case in test_cases:
        print(f"\n📝 Testing: {test_case['name']}")
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/feedback",
                json=test_case['data'],
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                feedback_ids.append(result['feedback_id'])
                print(f"   ✅ Success: {result['feedback_id']}")
                print(f"   📨 Message: {result['message']}")
            else:
                print(f"   ❌ Failed: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    return feedback_ids

def test_admin_dashboard():
    """Test admin dashboard functionality"""
    
    print("\n\n🔧 Testing Admin Dashboard")
    print("=" * 50)
    
    try:
        # Get dashboard data
        response = requests.get(
            f"{API_BASE_URL}/admin/dashboard",
            headers={'Authorization': f'Bearer {ADMIN_TOKEN}'}
        )
        
        if response.status_code == 200:
            dashboard = response.json()
            print(f"📊 Dashboard Statistics:")
            print(f"   - Pending Count: {dashboard['pending_count']}")
            print(f"   - Flagged Count: {dashboard['flagged_count']}")
            print(f"   - Approval Rate: {dashboard['quality_metrics'].get('approval_rate', 0):.1f}%")
            print(f"   - Total Reviewed: {dashboard['quality_metrics'].get('total_reviewed', 0)}")
        else:
            print(f"❌ Dashboard request failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Dashboard error: {e}")

def test_pending_feedback():
    """Test getting pending feedback"""
    
    print(f"\n📋 Getting Pending Feedback")
    print("-" * 30)
    
    try:
        response = requests.get(
            f"{API_BASE_URL}/admin/pending-feedback?limit=10",
            headers={'Authorization': f'Bearer {ADMIN_TOKEN}'}
        )
        
        if response.status_code == 200:
            pending_items = response.json()
            print(f"📝 Found {len(pending_items)} pending items:")
            
            for item in pending_items[:3]:  # Show first 3
                print(f"\n   ID: {item['feedback_id'][-8:]}")  # Last 8 chars
                print(f"   URL: {item['url']}")
                print(f"   Label: {'Phishing' if item['correct_label'] == 1 else 'Legitimate'}")
                print(f"   Status: {item['status']}")
                if item.get('flagged_reasons'):
                    print(f"   🚩 Flags: {', '.join(item['flagged_reasons'])}")
                if item.get('auto_validation_result'):
                    score = item['auto_validation_result']['validation_score']
                    print(f"   🤖 Auto Score: {score}/10")
                    
            return pending_items
        else:
            print(f"❌ Failed to get pending feedback: {response.status_code}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting pending feedback: {e}")
        return []

def test_admin_review(pending_items):
    """Test admin review functionality"""
    
    if not pending_items:
        print("\n⚠️ No pending items to review")
        return
        
    print(f"\n👨‍💼 Testing Admin Review")
    print("-" * 30)
    
    # Review first item (approve)
    first_item = pending_items[0]
    
    try:
        review_data = {
            "feedback_id": first_item['feedback_id'],
            "decision": "approve",
            "admin_comment": "Good quality feedback with clear explanation",
            "admin_id": "test_admin"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/admin/review-feedback",
            json=review_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {ADMIN_TOKEN}'
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Approved feedback: {result['feedback_id'][-8:]}")
            print(f"   Message: {result['message']}")
        else:
            print(f"❌ Review failed: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Review error: {e}")
    
    # Review second item if exists (reject)
    if len(pending_items) > 1:
        second_item = pending_items[1]
        
        try:
            review_data = {
                "feedback_id": second_item['feedback_id'],
                "decision": "reject",
                "admin_comment": "Insufficient detail in user comment",
                "admin_id": "test_admin"
            }
            
            response = requests.post(
                f"{API_BASE_URL}/admin/review-feedback",
                json=review_data,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {ADMIN_TOKEN}'
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"❌ Rejected feedback: {result['feedback_id'][-8:]}")
                print(f"   Message: {result['message']}")
            else:
                print(f"❌ Rejection failed: {response.status_code}")
                
        except Exception as e:
            print(f"❌ Rejection error: {e}")

def test_batch_operations(pending_items):
    """Test batch approval/rejection"""
    
    if len(pending_items) < 3:
        print("\n⚠️ Need at least 3 pending items for batch test")
        return
        
    print(f"\n📦 Testing Batch Operations")
    print("-" * 30)
    
    # Get remaining items for batch operation
    batch_items = [item['feedback_id'] for item in pending_items[2:4]]  # Items 3-4
    
    try:
        batch_data = {
            "feedback_ids": batch_items,
            "decision": "approve",
            "admin_comment": "Batch approval for testing",
            "admin_id": "test_admin"
        }
        
        response = requests.post(
            f"{API_BASE_URL}/admin/batch-review",
            json=batch_data,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {ADMIN_TOKEN}'
            }
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"📦 Batch operation completed:")
            print(f"   Total: {result['summary']['total']}")
            print(f"   Successful: {result['summary']['successful']}")
            print(f"   Failed: {result['summary']['failed']}")
        else:
            print(f"❌ Batch operation failed: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Batch error: {e}")

def main():
    """Run all tests"""
    
    print("🚀 Starting Feedback Review System Tests")
    print("=" * 60)
    print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 API Base URL: {API_BASE_URL}")
    print("=" * 60)
    
    # Test 1: Submit feedback
    feedback_ids = test_feedback_submission()
    
    # Wait a moment for processing
    time.sleep(2)
    
    # Test 2: Admin dashboard
    test_admin_dashboard()
    
    # Test 3: Get pending feedback
    pending_items = test_pending_feedback()
    
    # Test 4: Admin review
    test_admin_review(pending_items)
    
    # Test 5: Batch operations
    test_batch_operations(pending_items)
    
    # Final dashboard check
    print(f"\n📊 Final Dashboard Check")
    print("-" * 30)
    test_admin_dashboard()
    
    print(f"\n✅ Test Suite Completed!")
    print("=" * 60)
    print("Next Steps:")
    print("1. Check the admin dashboard at: frontend/admin_dashboard.html") 
    print("2. Review the data files in: data/")
    print("3. Verify the approval/rejection workflow")
    print("=" * 60)

if __name__ == "__main__":
    # Check if server is running
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            main()
        else:
            print("❌ Server is not responding properly")
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure it's running on localhost:8000")
        print("💡 Start server with: python main.py")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")