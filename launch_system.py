#!/usr/bin/env python3
"""
Test the running system and start frontend
"""
import requests
import time
import webbrowser
import http.server
import socketserver
import threading
import os
from pathlib import Path

def test_api():
    """Test if API is working"""
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ API Server is running!")
            health = response.json()
            print(f"📊 Status: {health.get('status', 'unknown')}")
            return True
        else:
            print(f"❌ API returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ API server is not running")
        return False
    except Exception as e:
        print(f"❌ Error testing API: {e}")
        return False

def test_url_scan():
    """Test URL scanning functionality"""
    try:
        test_data = {"url": "https://payp4l-security.com/login"}
        response = requests.post(
            "http://localhost:8000/scan-url", 
            json=test_data, 
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ URL Scanning works!")
            print(f"📊 Test URL: {test_data['url']}")
            print(f"🏷️ Classification: {result.get('classification', 'unknown')}")
            print(f"📈 Risk Score: {result.get('final_score', 0):.1f}/100")
            return True
        else:
            print(f"❌ Scan failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing scan: {e}")
        return False

def start_frontend():
    """Start frontend server"""
    try:
        os.chdir("frontend")
        
        def run_server():
            handler = http.server.SimpleHTTPRequestHandler
            with socketserver.TCPServer(("", 8080), handler) as httpd:
                print("🌐 Frontend server started at http://localhost:8080")
                httpd.serve_forever()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        os.chdir("..")
        time.sleep(2)
        return True
    except Exception as e:
        print(f"❌ Error starting frontend: {e}")
        return False

def main():
    """Main test and launch function"""
    print("🧪 TESTING AI PHISHING DETECTION SYSTEM")
    print("=" * 50)
    
    # Test API
    if not test_api():
        print("💡 Make sure to run 'python main.py' first")
        return
    
    # Test functionality
    if not test_url_scan():
        print("⚠️ URL scanning may have issues")
    
    # Start frontend
    if start_frontend():
        print("\n🎉 SYSTEM IS READY!")
        print("=" * 30)
        print("🌐 Frontend: http://localhost:8080")
        print("🔧 Backend:  http://localhost:8000")  
        print("📖 API Docs: http://localhost:8000/docs")
        print("=" * 30)
        
        # Open browser
        try:
            webbrowser.open("http://localhost:8080")
            print("🌍 Browser opened!")
        except:
            print("💡 Please open: http://localhost:8080")
        
        print("\n🚀 System running! Press Ctrl+C to stop.")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n👋 System stopped!")
    
if __name__ == "__main__":
    main()