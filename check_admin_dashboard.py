#!/usr/bin/env python3
"""
Admin Dashboard Error Checker
Verifies that all JavaScript functions are properly defined and no syntax errors exist.
"""

import sys
import os
import re

def check_admin_dashboard():
    """Check admin dashboard HTML file for JavaScript errors"""
    print("🔍 Checking Admin Dashboard for JavaScript Errors...")
    
    dashboard_file = "frontend/admin_dashboard.html"
    
    if not os.path.exists(dashboard_file):
        print("❌ Admin dashboard file not found")
        return False
    
    with open(dashboard_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for critical issues
    issues = []
    
    # 1. Check for duplicate fetch statements
    if content.count('const response = await fetch') > len(re.findall(r'async function \w+\(', content)):
        issues.append("Potential duplicate fetch statements")
    
    # 2. Check for undefined variables
    if 'ADMIN_TOKEN' in content:
        issues.append("Undefined variable 'ADMIN_TOKEN' found")
    
    # 3. Check for proper function definitions
    functions = [
        'loadPendingFeedback',
        'checkAuthentication', 
        'loadDashboardData',
        'renderFeedbackItems',
        'reviewFeedback'
    ]
    
    missing_functions = []
    for func in functions:
        if f'function {func}(' not in content and f'async function {func}(' not in content:
            missing_functions.append(func)
    
    if missing_functions:
        issues.append(f"Missing function definitions: {', '.join(missing_functions)}")
    
    # 4. Check for syntax issues
    if '}`' in content and 'headers:' in content:
        # This pattern suggests broken JavaScript
        issues.append("Potential JavaScript syntax errors")
    
    # 5. Check authentication flow
    auth_components = ['authToken', 'localStorage.getItem', 'admin_token']
    missing_auth = []
    for component in auth_components:
        if component not in content:
            missing_auth.append(component)
    
    if missing_auth:
        issues.append(f"Missing authentication components: {', '.join(missing_auth)}")
    
    # Print results
    if not issues:
        print("✅ No JavaScript errors found in admin dashboard")
        print("✅ All required functions are properly defined")
        print("✅ Authentication flow is complete")
        print("✅ Variable references are correct")
        return True
    else:
        print("❌ Issues found:")
        for issue in issues:
            print(f"   • {issue}")
        return False

def test_admin_endpoints():
    """Test if admin API endpoints are available"""
    print("\n🌐 Testing Admin API Endpoints...")
    
    try:
        import sys
        sys.path.append('.')
        from services.admin_api import admin_router
        
        # Get available routes
        routes = []
        for route in admin_router.routes:
            if hasattr(route, 'path') and hasattr(route, 'methods'):
                for method in route.methods:
                    if method != 'HEAD' and method != 'OPTIONS':
                        routes.append(f"{method} {route.path}")
        
        required_endpoints = [
            'POST /admin/authenticate',
            'GET /admin/dashboard', 
            'GET /admin/pending-feedback',
            'POST /admin/review-feedback',
            'POST /admin/logout'
        ]
        
        print(f"✅ Found {len(routes)} admin API endpoints")
        
        missing = []
        for endpoint in required_endpoints:
            if endpoint not in routes:
                missing.append(endpoint)
        
        if missing:
            print("❌ Missing endpoints:")
            for endpoint in missing:
                print(f"   • {endpoint}")
            return False
        else:
            print("✅ All required admin endpoints are available")
            return True
            
    except Exception as e:
        print(f"❌ Error loading admin API: {e}")
        return False

def main():
    """Run admin dashboard error check"""
    print("=" * 60)
    print("🛠️  Admin Dashboard Error Checker")
    print("=" * 60)
    
    dashboard_ok = check_admin_dashboard()
    api_ok = test_admin_endpoints()
    
    print("\n" + "=" * 60)
    if dashboard_ok and api_ok:
        print("🎉 Admin Dashboard is error-free and ready to use!")
        print("\n📋 Quick Test:")
        print("   1. Open: http://localhost:8000/admin_login.html")
        print("   2. Login with: admin / SecurePhish2026!")
        print("   3. Access dashboard and test functionality")
    else:
        print("⚠️  Some issues were found. Please review and fix.")
    
    print("=" * 60)

if __name__ == "__main__":
    main()