"""
Admin Authentication Service
Purpose: Secure authentication system for admin access with environment-based configuration
"""

import os
import hashlib
import hmac
import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class AdminAuthService:
    """Secure admin authentication service"""
    
    # Class-level session store — shared across all instances in the same process.
    # This works as a reliable fallback on Vercel where each request can hit the
    # same warm instance but a different AdminAuthService object would otherwise
    # have an empty active_sessions dict.
    _class_sessions: Dict[str, Any] = {}
    # Class-level revocation set for logout
    _revoked_tokens: set = set()
    
    def __init__(self, config_file: str = "admin_config.env"):
        # Resolve config path: prefer project root (two levels up from services/)
        if not os.path.isabs(config_file):
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_file = os.path.join(project_root, config_file)
        self.config_file = config_file
        self.failed_attempts = {}  # username -> {count, last_attempt}
        # Bind to class-level dict so all instances share the same session store
        self.active_sessions = AdminAuthService._class_sessions
        self.login_logs = []
        
        # Load configuration
        self.config = self._load_config()
        
        # Security settings
        self.max_attempts = int(self.config.get('MAX_LOGIN_ATTEMPTS', 5))
        self.timeout_minutes = int(self.config.get('LOGIN_TIMEOUT_MINUTES', 15))
        self.session_timeout = int(self.config.get('ADMIN_SESSION_TIMEOUT', 86400))  # 24 hours
        self.enable_logging = self.config.get('ENABLE_LOGIN_LOGGING', 'true').lower() == 'true'
        
        logger.info("Admin authentication service initialized")
    
    def _load_config(self) -> Dict[str, str]:
        """Load admin configuration from environment file and/or environment variables"""
        config = {}
        
        # 1. Load from file first (lowest priority)
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            value = value.split('#')[0].strip()
                            config[key.strip()] = value
                logger.info(f"Loaded admin config from {self.config_file}")
            except Exception as e:
                logger.error(f"Error loading config file {self.config_file}: {e}")
        else:
            logger.warning(f"Config file {self.config_file} not found, checking environment variables")
        
        # 2. Override with actual environment variables (higher priority — works on Vercel)
        for key in ['ADMIN_USERNAME', 'ADMIN_PASSWORD', 'ADMIN_TOKEN_SECRET',
                    'MAX_LOGIN_ATTEMPTS', 'LOGIN_TIMEOUT_MINUTES', 'ADMIN_SESSION_TIMEOUT']:
            env_val = os.environ.get(key)
            if env_val:
                config[key] = env_val
        
        # 3. Set hardcoded defaults only if still missing
        if 'ADMIN_USERNAME' not in config:
            config['ADMIN_USERNAME'] = 'admin'
        
        if 'ADMIN_PASSWORD' not in config:
            config['ADMIN_PASSWORD'] = 'SecureAdmin123!'
            logger.info("Using built-in default password")
        
        if 'ADMIN_TOKEN_SECRET' not in config:
            # Use a stable hardcoded default so tokens are verifiable across Vercel instances
            config['ADMIN_TOKEN_SECRET'] = 'phishing-admin-secret-key-2026-stable'
            logger.info("Using built-in default token secret")
        
        logger.info(f"Admin auth configured for user: {config.get('ADMIN_USERNAME')}")
        return config
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """
        Authenticate admin user
        
        Args:
            username: Admin username
            password: Admin password
            
        Returns:
            Dict containing success status, token, and error message if any
        """
        
        # Check for rate limiting
        if self._is_rate_limited(username):
            return {
                'success': False,
                'error': f'Too many failed attempts. Try again in {self.timeout_minutes} minutes.',
                'token': None
            }
        
        # Validate credentials
        if not self._validate_credentials(username, password):
            self._record_failed_attempt(username)
            
            # Log failed attempt
            if self.enable_logging:
                self._log_authentication_attempt(username, False, "Invalid credentials")
            
            return {
                'success': False,
                'error': 'Invalid username or password',
                'token': None
            }
        
        # Clear failed attempts on successful login
        if username in self.failed_attempts:
            del self.failed_attempts[username]
        
        # Generate session token
        token = self._generate_session_token(username)
        
        # Log successful attempt
        if self.enable_logging:
            self._log_authentication_attempt(username, True, "Successful login")
        
        logger.info(f"Admin user '{username}' authenticated successfully")
        
        return {
            'success': True,
            'token': token,
            'username': username,
            'expires_in': self.session_timeout
        }
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate session token — stateless HMAC verification.
        No dict lookup needed so works across Vercel instances.
        """
        if not token:
            return None
        
        # Check revocation list first
        if token in AdminAuthService._revoked_tokens:
            return None
        
        try:
            # Token format: base64url(username:expiry_ts):hmac_signature
            last_colon = token.rfind(':')
            if last_colon == -1:
                # Legacy dict-based token fallback
                if token in self.active_sessions:
                    session = self.active_sessions[token]
                    if datetime.now() <= session['expiry']:
                        return {'username': session['username'], 'token': token,
                                'expires': session['expiry'].isoformat()}
                return None
            
            encoded_payload = token[:last_colon]
            provided_sig = token[last_colon + 1:]
            
            # Verify HMAC signature
            secret = self.config.get('ADMIN_TOKEN_SECRET', 'phishing-admin-secret-key-2026-stable')
            expected_sig = hmac.new(
                secret.encode(), encoded_payload.encode(), hashlib.sha256
            ).hexdigest()
            
            if not secrets.compare_digest(provided_sig, expected_sig):
                return None
            
            # Decode payload
            payload = base64.urlsafe_b64decode(
                encoded_payload + '==' * (4 - len(encoded_payload) % 4)
            ).decode()
            username, expiry_ts_str = payload.rsplit(':', 1)
            expiry_ts = int(expiry_ts_str)
            
            # Check expiry
            if int(time.time()) > expiry_ts:
                return None
            
            return {
                'username': username,
                'token': token,
                'expires': datetime.fromtimestamp(expiry_ts).isoformat()
            }
        except Exception as e:
            logger.warning(f"Token validation error: {e}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a session token (logout) — adds to class-level revocation set"""
        AdminAuthService._revoked_tokens.add(token)
        # Also remove from legacy dict if present
        if token in self.active_sessions:
            username = self.active_sessions[token]['username']
            del self.active_sessions[token]
            if self.enable_logging:
                self._log_authentication_attempt(username, True, "Logout")
            logger.info(f"Session token revoked for user '{username}'")
        return True
    
    def _validate_credentials(self, username: str, password: str) -> bool:
        """Validate username and password against configuration"""
        expected_username = self.config.get('ADMIN_USERNAME')
        expected_password = self.config.get('ADMIN_PASSWORD')
        
        # Use secure comparison to prevent timing attacks
        username_match = secrets.compare_digest(username, expected_username)
        password_match = secrets.compare_digest(password, expected_password)
        
        return username_match and password_match
    
    def _is_rate_limited(self, username: str) -> bool:
        """Check if user is rate limited due to failed attempts"""
        if username not in self.failed_attempts:
            return False
        
        failed_data = self.failed_attempts[username]
        
        # Check if max attempts exceeded
        if failed_data['count'] < self.max_attempts:
            return False
        
        # Check if timeout period has passed
        time_since_last = datetime.now() - failed_data['last_attempt']
        timeout_period = timedelta(minutes=self.timeout_minutes)
        
        if time_since_last >= timeout_period:
            # Reset failed attempts
            del self.failed_attempts[username]
            return False
        
        return True
    
    def _record_failed_attempt(self, username: str):
        """Record a failed authentication attempt"""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = {
                'count': 0,
                'last_attempt': datetime.now()
            }
        
        self.failed_attempts[username]['count'] += 1
        self.failed_attempts[username]['last_attempt'] = datetime.now()
        
        logger.warning(f"Failed login attempt for '{username}' (attempt {self.failed_attempts[username]['count']})")
    
    def _generate_session_token(self, username: str) -> str:
        """Generate a stateless HMAC-signed session token verifiable without dict lookup"""
        expiry_ts = int((datetime.now() + timedelta(seconds=self.session_timeout)).timestamp())
        payload = f"{username}:{expiry_ts}"
        encoded_payload = base64.urlsafe_b64encode(payload.encode()).decode().rstrip('=')
        
        secret = self.config.get('ADMIN_TOKEN_SECRET', 'phishing-admin-secret-key-2026-stable')
        signature = hmac.new(secret.encode(), encoded_payload.encode(), hashlib.sha256).hexdigest()
        
        final_token = f"{encoded_payload}:{signature}"
        
        # Also store in class-level dict for backward compatibility / quick lookup
        expiry_dt = datetime.fromtimestamp(expiry_ts)
        AdminAuthService._class_sessions[final_token] = {
            'username': username,
            'created': datetime.now(),
            'expiry': expiry_dt,
            'last_access': datetime.now()
        }
        
        return final_token
    
    def _log_authentication_attempt(self, username: str, success: bool, details: str):
        """Log authentication attempt for security monitoring"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'username': username,
            'success': success,
            'details': details,
            'ip_address': 'localhost',  # In production, get from request
        }
        
        self.login_logs.append(log_entry)
        
        # Keep only last 1000 log entries
        if len(self.login_logs) > 1000:
            self.login_logs = self.login_logs[-1000:]
        
        # Also write to file if enabled
        try:
            log_file = 'logs/admin_auth.log'
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            with open(log_file, 'a') as f:
                f.write(f"{log_entry['timestamp']} - {username} - {'SUCCESS' if success else 'FAILED'} - {details}\\n")
        except Exception as e:
            logger.error(f"Error writing auth log: {e}")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics for monitoring"""
        return {
            'active_sessions': len(self.active_sessions),
            'failed_attempts_users': len(self.failed_attempts),
            'recent_login_attempts': len(self.login_logs),
            'last_successful_login': self._get_last_successful_login(),
            'system_status': 'operational'
        }
    
    def _get_last_successful_login(self) -> Optional[str]:
        """Get timestamp of last successful login"""
        successful_logins = [log for log in self.login_logs if log['success'] and log['details'] == 'Successful login']
        
        if successful_logins:
            return successful_logins[-1]['timestamp']
        return None
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions (call periodically)"""
        current_time = datetime.now()
        expired_tokens = [
            token for token, session in self.active_sessions.items()
            if current_time > session['expiry']
        ]
        
        for token in expired_tokens:
            del self.active_sessions[token]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired admin sessions")

# Global instance
admin_auth = AdminAuthService()