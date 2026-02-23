#!/usr/bin/env python3
"""
Quick Start Script for AI Phishing Detection System
Purpose: One-command setup and launch for hackathon demos
"""

import os
import sys
import subprocess
import time
import threading
from pathlib import Path

def print_banner():
    """Print system banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                  🛡️  AI PHISHING DETECTOR  🛡️                 ║  
    ║                                                              ║
    ║        Hybrid Deep Learning + Heuristic Detection           ║
    ║              🚀 Hackathon Ready System 🚀                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print("\033[96m" + banner + "\033[0m")

def check_dependencies():
    """Check if Python dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    try:
        import tensorflow
        import fastapi
        import pandas
        print("✅ Core dependencies found")
        return True
    except ImportError as e:
        print(f"❌ Missing dependencies: {e}")
        return False

def install_dependencies():
    """Install Python dependencies"""
    print("📦 Installing dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False

def generate_dataset():
    """Generate training dataset"""
    print("🤖 Generating phishing dataset...")
    
    if os.path.exists("data/generated_dataset.csv"):
        print("✅ Dataset already exists")
        return True
    
    try:
        subprocess.check_call([sys.executable, "dataset_generator.py"])
        print("✅ Dataset generated successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to generate dataset")
        return False

def train_model():
    """Train ML model"""
    print("🧠 Training deep learning model...")
    
    # Check if model already exists
    model_files = list(Path("models").glob("*.h5")) if Path("models").exists() else []
    if model_files:
        print("✅ Trained model found")
        return True
    
    try:
        subprocess.check_call([sys.executable, "models/train_model.py"])
        print("✅ Model trained successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to train model")
        return False

def setup_environment():
    """Setup environment configuration"""
    print("⚙️  Setting up environment...")
    
    if not os.path.exists(".env"):
        if os.path.exists(".env.example"):
            import shutil
            shutil.copy(".env.example", ".env")
            print("✅ Environment file created from template")
        else:
            # Create minimal .env file
            with open(".env", "w") as f:
                f.write("API_HOST=0.0.0.0\n")
                f.write("API_PORT=8000\n")
                f.write("DEBUG=true\n")
            print("✅ Basic environment file created")
    else:
        print("✅ Environment file exists")
    
    return True

def start_backend():
    """Start FastAPI backend server"""
    print("🚀 Starting backend server...")
    
    try:
        # Import and run the server
        import uvicorn
        from main import app
        
        # Run server in a separate thread
        def run_server():
            uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Wait a moment for server to start
        time.sleep(3)
        
        print("✅ Backend server started at http://localhost:8000")
        print("📖 API Documentation: http://localhost:8000/docs")
        return True
        
    except Exception as e:
        print(f"❌ Failed to start backend: {e}")
        return False

def start_frontend():
    """Start frontend server"""
    print("🌐 Starting frontend server...")
    
    try:
        import http.server
        import socketserver
        from functools import partial
        
        # Change to frontend directory
        os.chdir("frontend")
        
        # Create HTTP server
        handler = partial(http.server.SimpleHTTPRequestHandler)
        
        def run_frontend():
            with socketserver.TCPServer(("", 8080), handler) as httpd:
                print("✅ Frontend server started at http://localhost:8080")
                httpd.serve_forever()
        
        frontend_thread = threading.Thread(target=run_frontend, daemon=True)
        frontend_thread.start()
        
        # Go back to root directory
        os.chdir("..")
        
        time.sleep(2)
        return True
        
    except Exception as e:
        print(f"❌ Failed to start frontend: {e}")
        return False

def open_browser():
    """Open browser with the application"""
    print("🌍 Opening browser...")
    
    try:
        import webbrowser
        webbrowser.open("http://localhost:8080")
        print("✅ Browser opened")
    except:
        print("⚠️  Please manually open: http://localhost:8080")

def run_quick_demo():
    """Run a quick demo of the system"""
    print("\n🔬 Running Quick Demo...")
    
    try:
        from services.detection_engine import HybridDetectionEngine
        
        engine = HybridDetectionEngine()
        
        test_urls = [
            "https://www.paypal.com",  # Legitimate
            "http://payp4l-security.com/login",  # Phishing simulation
            "https://192.168.1.1/secure"  # IP-based suspicious
        ]
        
        print("\n" + "="*60)
        print("🧪 DEMO ANALYSIS RESULTS")
        print("="*60)
        
        for url in test_urls:
            print(f"\n🔗 Testing: {url}")
            result = engine.analyze_url(url)
            
            print(f"   📊 Risk Score: {result['final_score']:.1f}/100")
            print(f"   🏷️  Classification: {result['classification']}")
            print(f"   💬 Explanation: {result['explanation'][:80]}...")
        
        print("\n" + "="*60)
        print("✅ Demo completed! System is fully operational.")
        print("="*60)
        
    except Exception as e:
        print(f"⚠️  Demo failed: {e}")
        print("💡 System may still work - try the web interface")

def main():
    """Main setup and launch function"""
    print_banner()
    
    print("🚀 Starting AI Phishing Detection System Setup...\n")
    
    # Setup steps
    steps = [
        ("Dependencies", check_dependencies, install_dependencies),
        ("Environment", setup_environment, None),
        ("Dataset", generate_dataset, None),
        ("Model Training", train_model, None),
    ]
    
    # Execute setup steps
    for step_name, check_func, install_func in steps:
        if not check_func():
            if install_func:
                if not install_func():
                    print(f"❌ Setup failed at step: {step_name}")
                    return 1
            else:
                print(f"❌ Setup failed at step: {step_name}")
                return 1
        print()
    
    # Start services
    print("🎯 Launching services...\n")
    
    if not start_backend():
        return 1
    
    if not start_frontend():
        return 1
    
    print("\n🎉 SYSTEM READY!")
    print("=" * 50)
    print("🌐 Frontend:  http://localhost:8080")
    print("🔧 Backend:   http://localhost:8000")
    print("📖 API Docs: http://localhost:8000/docs")
    print("=" * 50)
    
    # launch browser
    open_browser()
    
    # Run demo
    run_quick_demo()
    
    print("\n🏃 Keep this terminal running to maintain the servers")
    print("🛑 Press Ctrl+C to stop the system\n")
    
    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down AI Phishing Detection System...")
        print("Thanks for using our system! 🛡️")
        return 0

if __name__ == "__main__":
    sys.exit(main())