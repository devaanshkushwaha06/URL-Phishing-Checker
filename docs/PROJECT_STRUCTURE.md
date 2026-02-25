# 📁 Project Structure

This document outlines the organized structure of the AI Phishing Detection System after cleanup.

## 🗂️ Root Directory Structure

```
URL-Phising/                     # Main project directory
├── 📁 api/                      # Vercel serverless deployment
│   ├── index.py                 # Main API entry point for production
│   └── requirements.txt         # Python dependencies for deployment
├── 📁 frontend/                 # Web interface (HTML/CSS/JS)
│   ├── index.html              # Main user interface
│   ├── admin_login.html        # Admin authentication page
│   ├── admin_dashboard.html    # Admin management interface
│   ├── script.js              # Frontend JavaScript logic
│   └── style.css              # UI styling
├── 📁 services/                 # Core business logic
│   ├── admin_api.py            # Admin API endpoints
│   ├── admin_auth.py           # Authentication system
│   ├── detection_engine.py     # Hybrid ML+Heuristic engine
│   └── feedback_review_system.py # Feedback processing
├── 📁 data/                     # Runtime data storage
│   ├── feedback.json           # User feedback data
│   ├── quality_metrics.json    # Performance tracking
│   └── *.csv                   # Dataset files
├── 📁 models/                   # Machine learning models
│   └── train_model.py          # Model training pipeline
├── 📁 logs/                     # System logs
│   ├── admin_auth.log          # Admin authentication logs
│   └── scan_requests.json      # API usage logs
├── 📁 docs/                     # Documentation (organized)
│   ├── ADMIN_SETUP.md          # Admin system setup guide
│   ├── DEPLOYMENT.md           # Production deployment guide
│   ├── FEEDBACK_REVIEW_SYSTEM.md # Feedback system documentation
│   └── PROJECT_STRUCTURE.md    # This file
├── main.py                     # Development server
├── vercel.json                 # Vercel deployment configuration
├── requirements.txt            # Python dependencies
├── README.md                   # Main project documentation
├── .env.example               # Environment variables template
├── admin_config.env.example   # Admin config template
├── .gitignore                 # Git ignore rules
└── .vercelignore              # Vercel ignore rules
```

## 🧹 Files Removed During Cleanup

The following files were removed to streamline the project:

### 🗑️ Deleted Files:
- `__pycache__/` - Python bytecode cache
- `services/__pycache__/` - Service cache files
- `admin_config.env` - **Removed for security** (contained secrets)
- `launch_system.py` - Utility script (redundant)
- `quick_start.py` - Setup script (one-time use)
- `setup_admin.py` - Admin setup utility
- `deploy_setup.py` - Deployment script
- `check_admin_dashboard.py` - Testing utility
- `dataset_generator.py` - Development utility (moved to models/)
- `test_complete_system.py` - Test file
- `test_feedback_system.py` - Test file  
- `test_system.py` - Test file

### 📝 Organized Files:
- Documentation moved to `docs/` folder
- All sensitive files properly ignored in `.gitignore`
- Cache directories removed and ignored

## 🚀 Quick Start Guide

### Development:
```bash
# Run development server
python main.py
```

### Production (Vercel):
```bash
# Deploy to Vercel
vercel deploy
```

## 🔧 Key Configuration Files

### Environment Setup:
- Copy `.env.example` to `.env` and configure
- Copy `admin_config.env.example` to `admin_config.env` for admin features

### Vercel Deployment:
- `vercel.json` - Configured for Python serverless functions
- `api/` - Production API endpoint
- Environment variables set in Vercel dashboard

## 📋 File Purposes

| Directory | Purpose | Important Files |
|-----------|---------|----------------|
| `api/` | Production deployment | `index.py` (main API) |
| `frontend/` | User interface | `index.html`, `script.js` |
| `services/` | Core business logic | `detection_engine.py` |
| `data/` | Runtime storage | Auto-generated files |
| `models/` | ML components | `train_model.py` |
| `logs/` | System monitoring | Auto-generated logs |
| `docs/` | Documentation | Setup guides |

This structure provides clear separation of concerns while maintaining simplicity for both development and production deployment.