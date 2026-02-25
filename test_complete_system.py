#!/usr/bin/env python3
"""
Complete System Test for AI Phishing Detection with Admin Authentication
Tests the entire workflow including feedback review and admin authentication.
"""

import sys
import os
sys.path.append('.')

def test_admin_auth():
    """Test admin authentication system"""
    print("🔐 Testing Admin Authentication System...")
    
    try:
        from services.admin_auth import admin_auth
        
        # Test successful login
        result = admin_auth.authenticate('admin', 'SecurePhish2026!')
        if result['success']:
            print("✅ Admin login successful")
            print(f"   Token generated: {'token' in result}")
            
            # Test token validation
            token = result['token']
            validation = admin_auth.validate_token(token)
            if validation is not None:
                print("✅ Token validation successful")
                print(f"   Username: {validation['username']}")
            else:
                print("❌ Token validation failed")
                return False
        else:
            print("❌ Admin login failed")
            return False
            
        # Test invalid login
        result = admin_auth.authenticate('admin', 'wrong-password')
        if not result['success']:
            print("✅ Invalid login properly rejected")
        else:
            print("❌ Invalid login was accepted (security issue!)")
            return False
            
        return True
        
    except Exception as e:
        print(f"❌ Admin auth test failed: {e}")
        return False

def test_feedback_system():
    """Test feedback review system"""
    print("\n📋 Testing Feedback Review System...")
    
    try:
        from services.feedback_review_system import FeedbackReviewSystem
        
        # Create feedback review system instance
        feedback_review_system = FeedbackReviewSystem()
        
        # Test feedback submission
        result = feedback_review_system.submit_user_feedback(
            url='https://example-phishing.com',
            correct_label=1,  # 1 = phishing
            user_comment='This is clearly a phishing site',
            confidence_level=5,
            user_expertise='expert',
            user_id='test-user-123'
        )
        if 'feedback_id' in result:
            print("✅ Feedback submission successful")
            print(f"   Feedback ID: {result['feedback_id']}")
            print(f"   Status: {result['status']}")
            
            # Test getting pending feedback
            pending = feedback_review_system.get_pending_feedback()
            print(f"✅ Pending feedback retrieved: {len(pending)} items")
            
            return True
        else:
            print(f"❌ Feedback submission failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Feedback system test failed: {e}")
        return False

def test_api_integration():
    """Test API integration"""
    print("\n🌐 Testing API Integration...")
    
    try:
        from services.admin_api import admin_router
        print("✅ Admin API router loaded successfully")
        
        # Check if admin endpoints are available
        routes = []
        for route in admin_router.routes:
            if hasattr(route, 'path'):
                routes.append(f"{route.methods} {route.path}")
        
        print(f"✅ Admin API routes available: {len(routes)}")
        for route in routes[:5]:  # Show first 5 routes
            print(f"   {route}")
        
        return True
        
    except Exception as e:
        print(f"❌ API integration test failed: {e}")
        return False

def test_security_config():
    """Test security configuration"""
    print("\n🛡️  Testing Security Configuration...")
    
    try:
        # Check if config file exists and is properly protected
        config_file = "admin_config.env"
        gitignore_file = ".gitignore"
        
        if os.path.exists(config_file):
            print("✅ Admin config file exists")
        else:
            print("❌ Admin config file missing")
            return False
            
        if os.path.exists(gitignore_file):
            with open(gitignore_file, 'r') as f:
                gitignore_content = f.read()
                if config_file in gitignore_content:
                    print("✅ Admin config file is protected in .gitignore")
                else:
                    print("⚠️  Admin config file not in .gitignore (security risk)")
        else:
            print("⚠️  .gitignore file not found")
            
        return True
        
    except Exception as e:
        print(f"❌ Security config test failed: {e}")
        return False

def main():
    """Run complete system test"""
    print("=" * 60)
    print("🚀 AI Phishing Detection - Complete System Test")
    print("=" * 60)
    
    tests = [
        ("Admin Authentication", test_admin_auth),
        ("Feedback Review System", test_feedback_system),
        ("API Integration", test_api_integration),
        ("Security Configuration", test_security_config),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        if test_func():
            passed += 1
        print()
    
    print("=" * 60)
    print(f"🎯 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All systems operational! Your AI Phishing Detection system is ready.")
        print("\n📋 Quick Start:")
        print("   1. Run: python main.py")
        print("   2. Open: http://localhost:8000")
        print("   3. Admin access: Click 'Admin' button in header")
        print("   4. Login with: admin / SecurePhish2026!")
    else:
        print("⚠️  Some tests failed. Please check issues above.")
        
    print("=" * 60)

if __name__ == "__main__":
    main()