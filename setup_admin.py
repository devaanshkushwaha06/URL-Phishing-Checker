"""
Admin Setup Script  
Purpose: Quick setup for secure admin authentication system
"""

import os
import secrets
import getpass
from pathlib import Path

def generate_secure_token():
    """Generate a secure random token for JWT secret"""
    return secrets.token_urlsafe(32)

def validate_password_strength(password):
    """Basic password strength validation"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    checks = {
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password), 
        'digit': any(c.isdigit() for c in password),
        'special': any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
    }
    
    failed_checks = [check for check, passed in checks.items() if not passed]
    
    if len(failed_checks) > 1:
        return False, f"Password should include: {', '.join(failed_checks)}"
    
    return True, "Password strength: Good"

def setup_admin_config():
    """Interactive setup for admin configuration"""
    print("="*60)
    print("🛡️  AI Phishing Detection - Admin Setup")
    print("="*60)
    print()
    
    # Check if config already exists
    config_file = "admin_config.env"
    if os.path.exists(config_file):
        print(f"⚠️  Configuration file '{config_file}' already exists.")
        overwrite = input("Do you want to overwrite it? (y/N): ").lower().strip()
        if overwrite != 'y':
            print("Setup cancelled.")
            return
        print()
    
    print("This script will help you set up secure admin authentication.")
    print("All settings can be changed later by editing admin_config.env")
    print()
    
    config = {}
    
    # Admin username
    print("1. Admin Username Configuration")
    print("   Default username is 'admin' (recommended to change)")
    username = input("   Enter admin username (or press Enter for 'admin'): ").strip()
    config['ADMIN_USERNAME'] = username if username else 'admin'
    print(f"   ✓ Username set to: {config['ADMIN_USERNAME']}")
    print()
    
    # Admin password
    print("2. Admin Password Configuration")
    print("   Password should be at least 8 characters with mixed case, numbers, and symbols")
    
    while True:
        password = getpass.getpass("   Enter admin password: ").strip()
        if not password:
            print("   ❌ Password cannot be empty")
            continue
            
        is_strong, message = validate_password_strength(password)
        print(f"   {message}")
        
        if is_strong:
            # Confirm password
            confirm_password = getpass.getpass("   Confirm admin password: ").strip()
            if password == confirm_password:
                config['ADMIN_PASSWORD'] = password
                print("   ✓ Password configured successfully")
                break
            else:
                print("   ❌ Passwords do not match. Please try again.")
        else:
            retry = input("   Use this password anyway? (y/N): ").lower().strip()
            if retry == 'y':
                config['ADMIN_PASSWORD'] = password
                print("   ✓ Password configured (weak password warning)")
                break
    print()
    
    # Security settings
    print("3. Security Settings")
    
    # Session timeout
    print("   Session timeout (how long admin stays logged in):")
    print("   1. 8 hours (28800 seconds) - High security")
    print("   2. 24 hours (86400 seconds) - Default")  
    print("   3. 7 days (604800 seconds) - Convenience")
    
    while True:
        timeout_choice = input("   Choose session timeout (1-3) or enter custom seconds: ").strip()
        if timeout_choice == '1':
            config['ADMIN_SESSION_TIMEOUT'] = '28800'
            break
        elif timeout_choice == '2':
            config['ADMIN_SESSION_TIMEOUT'] = '86400'
            break
        elif timeout_choice == '3':
            config['ADMIN_SESSION_TIMEOUT'] = '604800'
            break
        elif timeout_choice.isdigit():
            config['ADMIN_SESSION_TIMEOUT'] = timeout_choice
            break
        else:
            print("   Please enter 1, 2, 3, or a number of seconds")
    
    print(f"   ✓ Session timeout: {config['ADMIN_SESSION_TIMEOUT']} seconds")
    
    # Max login attempts
    max_attempts = input("   Max login attempts before lockout (default 5): ").strip()
    config['MAX_LOGIN_ATTEMPTS'] = max_attempts if max_attempts.isdigit() else '5'
    print(f"   ✓ Max login attempts: {config['MAX_LOGIN_ATTEMPTS']}")
    
    # Login timeout
    lockout_time = input("   Lockout timeout in minutes (default 15): ").strip()
    config['LOGIN_TIMEOUT_MINUTES'] = lockout_time if lockout_time.isdigit() else '15'
    print(f"   ✓ Lockout timeout: {config['LOGIN_TIMEOUT_MINUTES']} minutes")
    print()
    
    # Generate secure token
    print("4. Generating Security Token")
    config['ADMIN_TOKEN_SECRET'] = generate_secure_token()
    print("   ✓ Secure JWT secret generated")
    print()
    
    # Additional settings
    config['REQUIRE_STRONG_PASSWORD'] = 'true'
    config['ENABLE_LOGIN_LOGGING'] = 'true'
    
    # Write configuration file
    print("5. Writing Configuration File")
    
    config_content = f"""# AI Phishing Detection - Admin Configuration
# Generated by setup script on {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# SECURITY WARNING: Keep this file secure and never commit to Git!

# Admin Authentication
ADMIN_USERNAME={config['ADMIN_USERNAME']}
ADMIN_PASSWORD={config['ADMIN_PASSWORD']}
ADMIN_TOKEN_SECRET={config['ADMIN_TOKEN_SECRET']}
ADMIN_SESSION_TIMEOUT={config['ADMIN_SESSION_TIMEOUT']}

# Security Settings
MAX_LOGIN_ATTEMPTS={config['MAX_LOGIN_ATTEMPTS']}
LOGIN_TIMEOUT_MINUTES={config['LOGIN_TIMEOUT_MINUTES']}
REQUIRE_STRONG_PASSWORD={config['REQUIRE_STRONG_PASSWORD']}
ENABLE_LOGIN_LOGGING={config['ENABLE_LOGIN_LOGGING']}

# Additional Settings (can be customized)
DEBUG_MODE=false
MAX_PENDING_DISPLAY=100
SESSION_CLEANUP_HOURS=48
"""
    
    try:
        with open(config_file, 'w') as f:
            f.write(config_content)
        print(f"   ✓ Configuration saved to {config_file}")
    except Exception as e:
        print(f"   ❌ Error writing config file: {e}")
        return
    
    # Security checklist
    print()
    print("="*60)
    print("🔒 Security Setup Complete!")
    print("="*60)
    print()
    print("📋 Security Checklist:")
    print(f"   ✓ Admin username: {config['ADMIN_USERNAME']}")
    print(f"   ✓ Secure password configured")
    print(f"   ✓ Session timeout: {int(config['ADMIN_SESSION_TIMEOUT'])//3600} hour(s)")
    print(f"   ✓ Login protection: {config['MAX_LOGIN_ATTEMPTS']} attempts max")
    print(f"   ✓ Secure token generated")
    print(f"   ✓ Login logging enabled")
    print()
    print("🚀 Next Steps:")
    print("   1. Start the server: python main.py")
    print("   2. Open your browser to: http://localhost:8000")
    print("   3. Click 'Admin' link to access admin dashboard")
    print("   4. Login with your configured credentials")
    print()
    print("⚡ Quick Links:")
    print("   • Main site: http://localhost:8000")
    print("   • Admin login: http://localhost:8000/frontend/admin_login.html")  
    print("   • API docs: http://localhost:8000/docs")
    print()
    print("🛡️ Security Reminders:")
    print(f"   • {config_file} is excluded from Git (check .gitignore)")
    print("   • Log files are in logs/admin_auth.log")
    print("   • Use HTTPS in production")
    print("   • Regularly review access logs")
    print("   • Backup configuration securely")
    print()
    print("="*60)

def main():
    """Main setup function"""
    try:
        setup_admin_config()
    except KeyboardInterrupt:
        print("\\n\\nSetup cancelled by user.")
    except Exception as e:
        print(f"\\n❌ Setup error: {e}")
        print("Please check the error and try again.")

if __name__ == "__main__":
    main()