# Data Directory

This directory contains data files used by the AI Phishing Detection System.

⚠️ **Security Notice**: Actual data files with URLs and user feedback are excluded from the repository for security and privacy reasons.

## File Structure

### Template Files (included in repo):
- `feedback_dataset_template.csv` - Template for feedback dataset format
- `.gitkeep` - Keeps directory structure in git

### Runtime Files (created by application):
- `feedback.json` - User feedback data (excluded from repo)
- `feedback_dataset.csv` - CSV format feedback (excluded from repo) 
- `generated_dataset.csv` - Generated training data (excluded from repo)
- `admin_decisions.json` - Admin review decisions (excluded from repo)
- `pending_feedback.json` - Feedback awaiting review (excluded from repo)
- `approved_feedback_dataset.csv` - Approved feedback (excluded from repo)
- `rejected_feedback.json` - Rejected feedback (excluded from repo)
- `reviewed_feedback.json` - Reviewed feedback (excluded from repo)
- `quality_metrics.json` - Quality metrics (excluded from repo)

## Data Privacy

All actual data files containing URLs, user feedback, and analysis results are:
- ✅ Excluded from git via `.gitignore`
- ✅ Excluded from deployment via `.vercelignore`
- ✅ Created dynamically by the application
- ✅ Stored locally only

## Setup

The application will automatically create necessary data files when it runs for the first time.