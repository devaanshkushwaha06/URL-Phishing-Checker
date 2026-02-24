#!/usr/bin/env python3
"""
Quick Vercel Deployment Setup Script
Automates the setup process for deploying to Vercel
"""

import os
import json
import subprocess
import sys
from pathlib import Path

def print_banner():
    """Print deployment banner"""
    print("=" * 60)
    print("🚀 AI Phishing Detection - Vercel Deployment Setup")
    print("=" * 60)
    print()

def check_requirements():
    """Check if required files exist"""
    required_files = [
        "vercel.json",
        "api/index.py",
        "api/requirements.txt",
        "frontend/index.html",
        "frontend/script.js",
        "frontend/style.css"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\n💡 Please ensure all files are present before deployment.")
        return False
    
    print("✅ All required files are present")
    return True

def check_vercel_cli():
    """Check if Vercel CLI is installed"""
    try:
        result = subprocess.run(['vercel', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Vercel CLI installed: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    
    print("❌ Vercel CLI not found")
    print("💡 Install with: npm i -g vercel")
    return False

def setup_environment():
    """Setup environment configuration"""
    env_example = ".env.example"
    env_local = ".env"
    
    if os.path.exists(env_example) and not os.path.exists(env_local):
        print(f"📝 Copying {env_example} to {env_local}")
        with open(env_example, 'r') as src, open(env_local, 'w') as dst:
            dst.write(src.read())
        print("💡 Please update .env file with your actual values")
    else:
        print("✅ Environment configuration ready")

def validate_vercel_json():
    """Validate vercel.json configuration"""
    try:
        with open('vercel.json', 'r') as f:
            config = json.load(f)
        
        # Check required sections
        required_sections = ['builds', 'routes']
        for section in required_sections:
            if section not in config:
                print(f"❌ Missing '{section}' in vercel.json")
                return False
        
        print("✅ Vercel configuration is valid")
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in vercel.json: {e}")
        return False
    except FileNotFoundError:
        print("❌ vercel.json not found")
        return False

def show_deployment_commands():
    """Show deployment commands"""
    print("\n🚀 Ready for deployment! Choose one option:")
    print("\n1️⃣  Deploy via Vercel CLI:")
    print("   vercel login")
    print("   vercel --prod")
    print("\n2️⃣  Deploy via Vercel Dashboard:")
    print("   - Go to https://vercel.com")
    print("   - Click 'New Project'")
    print("   - Import your GitHub repository")
    print("   - Configure environment variables")

def show_environment_variables():
    """Show required environment variables"""
    print("\n🔧 Required Environment Variables for Vercel:")
    print("─" * 40)
    
    env_vars = [
        ("VIRUSTOTAL_API_KEY", "Your VirusTotal API key (optional but recommended)"),
        ("VALIDATION_CONFIDENCE_THRESHOLD", "80 (default)"),
        ("AUTO_APPROVE_THRESHOLD", "80 (default)"),
        ("ENABLE_FEEDBACK_VALIDATION", "true"),
    ]
    
    for var, desc in env_vars:
        print(f"• {var}")
        print(f"  {desc}")
        print()

def main():
    """Main deployment setup function"""
    print_banner()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Validate configuration
    if not validate_vercel_json():
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Check Vercel CLI (optional)
    has_cli = check_vercel_cli()
    
    # Show deployment options
    show_deployment_commands()
    
    # Show environment variables
    show_environment_variables()
    
    print("\n📚 For detailed instructions, see DEPLOYMENT.md")
    print("\n✅ Setup complete! Your project is ready for Vercel deployment.")
    
    if has_cli:
        deploy_now = input("\n🚀 Deploy now with Vercel CLI? (y/N): ").lower().strip()
        if deploy_now == 'y':
            print("\nStarting deployment...")
            try:
                subprocess.run(['vercel', '--prod'], check=True)
                print("\n🎉 Deployment initiated successfully!")
            except subprocess.CalledProcessError:
                print("\n❌ Deployment failed. Please check the output above.")
            except KeyboardInterrupt:
                print("\n⏹️  Deployment cancelled by user.")

if __name__ == "__main__":
    main()