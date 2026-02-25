/**
 * AI Phishing Detection System - Frontend JavaScript
 * Purpose: Handle user interactions, API calls, and UI updates
 */

// Configuration - Auto-detect environment
const API_BASE_URL = (() => {
    // Check if running on localhost (development)
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        return 'http://localhost:8000';
    }
    // Production - use relative path for Vercel deployment
    return '';
})();

let currentAnalysisResult = null;

// DOM Elements
const elements = {
    urlInput: document.getElementById('url-input'),
    scanBtn: document.getElementById('scan-btn'),
    loadingSection: document.getElementById('loading-section'),
    resultsSection: document.getElementById('results-section'),
    feedbackSection: document.getElementById('feedback-section'),
    
    // Results elements
    riskScore: document.getElementById('risk-score'),
    gaugeFill: document.getElementById('gauge-fill'),
    classificationBadge: document.getElementById('classification-badge'),
    classificationIcon: document.getElementById('classification-icon'),
    classificationText: document.getElementById('classification-text'),
    
    // Analysis details
    analyzedUrl: document.getElementById('analyzed-url'),
    analyzedDomain: document.getElementById('analyzed-domain'),
    processingTime: document.getElementById('processing-time'),
    explanationText: document.getElementById('explanation-text'),
    
    // Score bars
    mlScoreFill: document.getElementById('ml-score-fill'),
    mlScoreValue: document.getElementById('ml-score-value'),
    heuristicScoreFill: document.getElementById('heuristic-score-fill'),
    heuristicScoreValue: document.getElementById('heuristic-score-value'),
    apiScoreFill: document.getElementById('api-score-fill'),
    apiScoreValue: document.getElementById('api-score-value'),
    
    // Feedback elements
    correctBtn: document.getElementById('correct-btn'),
    incorrectBtn: document.getElementById('incorrect-btn'),
    feedbackForm: document.getElementById('feedback-form'),
    submitFeedbackBtn: document.getElementById('submit-feedback-btn'),
    cancelFeedbackBtn: document.getElementById('cancel-feedback-btn'),
    userComment: document.getElementById('user-comment'),
    feedbackSuccess: document.getElementById('feedback-success'),
    
    // Status elements
    apiStatus: document.getElementById('api-status'),
    statusIndicator: document.getElementById('status-indicator'),
    statusText: document.getElementById('status-text')
};

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    checkApiStatus();
    setupKeyboardShortcuts();
});

/**
 * Initialize all event listeners
 */
function initializeEventListeners() {
    // URL scanning
    elements.scanBtn.addEventListener('click', handleUrlScan);
    elements.urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            handleUrlScan();
        }
    });
    
    // Input validation
    elements.urlInput.addEventListener('input', validateInput);
    
    // Feedback system
    elements.correctBtn.addEventListener('click', () => handleFeedbackChoice(true));
    elements.incorrectBtn.addEventListener('click', () => handleFeedbackChoice(false));
    elements.submitFeedbackBtn.addEventListener('click', handleFeedbackSubmission);
    elements.cancelFeedbackBtn.addEventListener('click', hideFeedbackForm);
    
    // Auto-resize textarea
    elements.userComment.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = this.scrollHeight + 'px';
    });
}

/**
 * Setup keyboard shortcuts
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + Enter to scan
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            handleUrlScan();
        }
    });
}

/**
 * Validate URL input
 */
function validateInput() {
    const url = elements.urlInput.value.trim();
    const isValid = url.length > 0;
    
    elements.scanBtn.disabled = !isValid;
    elements.urlInput.style.borderColor = isValid || url.length === 0 ? '#e5e7eb' : '#ef4444';
}

/**
 * Handle URL scanning
 */
async function handleUrlScan() {
    const url = elements.urlInput.value.trim();
    
    if (!url) {
        showToast('Please enter a URL to analyze', 'warning');
        return;
    }
    
    // Show loading state
    showLoadingState();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }
        
        const result = await response.json();
        currentAnalysisResult = result;
        
        // Simulate minimum loading time for better UX
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        displayResults(result);
        
    } catch (error) {
        console.error('Analysis error:', error);
        showToast(`Analysis failed: ${error.message}`, 'error');
        hideLoadingState();
    }
}

/**
 * Show loading state with animations
 */
function showLoadingState() {
    elements.resultsSection.style.display = 'none';
    elements.feedbackSection.style.display = 'none';
    elements.loadingSection.style.display = 'block';
    elements.scanBtn.disabled = true;
    elements.scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> <span class="button-text">Analyzing...</span>';
    
    // Animate analysis steps
    const steps = document.querySelectorAll('.analysis-step');
    steps.forEach(step => {
        step.style.opacity = '0';
    });
}

/**
 * Hide loading state
 */
function hideLoadingState() {
    elements.loadingSection.style.display = 'none';
    elements.scanBtn.disabled = false;
    elements.scanBtn.innerHTML = '<i class="fas fa-search"></i> <span class="button-text">Analyze</span>';
}

/**
 * Display analysis results with animations
 */
function displayResults(result) {
    hideLoadingState();
    
    // Show results section
    elements.resultsSection.style.display = 'block';
    elements.feedbackSection.style.display = 'block';
    
    // Animate risk score
    animateRiskScore(result.final_score);
    
    // Update classification badge
    updateClassificationBadge(result.classification.toLowerCase(), result.classification);
    
    // Update URL information
    elements.analyzedUrl.textContent = result.url;
    elements.analyzedDomain.textContent = result.domain;
    elements.processingTime.textContent = `${result.processing_time_ms.toFixed(1)}ms`;
    
    // Update explanation
    elements.explanationText.textContent = result.explanation;
    
    // Animate score breakdowns
    setTimeout(() => {
        animateScoreBar(elements.mlScoreFill, elements.mlScoreValue, 
                       result.deep_learning_probability * 100, '%');
        
        animateScoreBar(elements.heuristicScoreFill, elements.heuristicScoreValue, 
                       (result.heuristic_score / 40) * 100, `${result.heuristic_score.toFixed(1)}/40`);
        
        animateScoreBar(elements.apiScoreFill, elements.apiScoreValue, 
                       (result.api_score / 20) * 100, `${result.api_score.toFixed(1)}/20`);
    }, 500);
    
    // Scroll to results
    elements.resultsSection.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Animate risk score gauge
 */
function animateRiskScore(score) {
    let currentScore = 0;
    const targetScore = Math.min(Math.max(score, 0), 100);
    const duration = 2000;
    const steps = 60;
    const increment = targetScore / steps;
    const stepDuration = duration / steps;
    
    const animation = setInterval(() => {
        currentScore += increment;
        
        if (currentScore >= targetScore) {
            currentScore = targetScore;
            clearInterval(animation);
        }
        
        // Update score display
        elements.riskScore.textContent = Math.round(currentScore);
        
        // Update gauge fill (simplified visual representation)
        const percentage = (currentScore / 100) * 360;
        elements.gaugeFill.style.background = `conic-gradient(from 0deg, 
            ${getGaugeColor(currentScore)} 0deg ${percentage}deg, 
            #f3f4f6 ${percentage}deg 360deg)`;
    }, stepDuration);
}

/**
 * Get gauge color based on score
 */
function getGaugeColor(score) {
    if (score <= 30) return '#22c55e';
    if (score <= 60) return '#eab308';
    return '#ef4444';
}

/**
 * Update classification badge
 */
function updateClassificationBadge(className, text) {
    // Remove existing classes
    elements.classificationBadge.className = 'classification-badge';
    
    // Add new class
    elements.classificationBadge.classList.add(className);
    
    // Update icon and text
    let iconClass;
    switch (className) {
        case 'safe':
            iconClass = 'fas fa-check-circle';
            break;
        case 'suspicious':
            iconClass = 'fas fa-exclamation-triangle';
            break;
        case 'phishing':
            iconClass = 'fas fa-times-circle';
            break;
        default:
            iconClass = 'fas fa-question-circle';
    }
    
    elements.classificationIcon.className = `classification-icon ${iconClass}`;
    elements.classificationText.textContent = text;
}

/**
 * Animate score bars
 */
function animateScoreBar(fillElement, valueElement, percentage, displayValue) {
    fillElement.style.width = '0%';
    valueElement.textContent = displayValue;
    
    // Animate width
    setTimeout(() => {
        fillElement.style.width = `${Math.min(percentage, 100)}%`;
    }, 100);
}

/**
 * Handle feedback choice (correct/incorrect)
 */
function handleFeedbackChoice(isCorrect) {
    if (isCorrect) {
        // User agreed with analysis
        showToast('Thank you for confirming our analysis!', 'success');
        submitFeedback(getCurrentCorrectLabel(), 'User confirmed analysis was correct');
    } else {
        // User disagreed - show form
        showFeedbackForm();
    }
}

/**
 * Get current correct label based on analysis result
 */
function getCurrentCorrectLabel() {
    if (!currentAnalysisResult) return 0;
    
    const classification = currentAnalysisResult.classification.toLowerCase();
    return classification === 'phishing' ? 1 : 0;
}

/**
 * Show feedback form
 */
function showFeedbackForm() {
    elements.feedbackForm.style.display = 'block';
    elements.correctBtn.style.display = 'none';
    elements.incorrectBtn.style.display = 'none';
    
    // Pre-select opposite of current analysis
    const currentLabel = getCurrentCorrectLabel();
    const correctRadio = document.querySelector(`input[name="correct-label"][value="${1 - currentLabel}"]`);
    if (correctRadio) {
        correctRadio.checked = true;
    }
}

/**
 * Hide feedback form
 */
function hideFeedbackForm() {
    elements.feedbackForm.style.display = 'none';
    elements.correctBtn.style.display = 'inline-flex';
    elements.incorrectBtn.style.display = 'inline-flex';
    
    // Clear form
    document.querySelectorAll('input[name="correct-label"]').forEach(radio => {
        radio.checked = false;
    });
    elements.userComment.value = '';
}

/**
 * Handle feedback form submission
 */
async function handleFeedbackSubmission() {
    const selectedLabel = document.querySelector('input[name="correct-label"]:checked');
    
    if (!selectedLabel) {
        showToast('Please select the correct classification', 'warning');
        return;
    }
    
    const correctLabel = parseInt(selectedLabel.value);
    const comment = elements.userComment.value.trim();
    
    elements.submitFeedbackBtn.disabled = true;
    elements.submitFeedbackBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Submitting...';
    
    try {
        await submitFeedback(correctLabel, comment);
        
        // Show success message
        hideFeedbackForm();
        elements.feedbackSuccess.style.display = 'block';
        setTimeout(() => {
            elements.feedbackSuccess.style.display = 'none';
        }, 5000);
        
    } catch (error) {
        showToast(`Failed to submit feedback: ${error.message}`, 'error');
    } finally {
        elements.submitFeedbackBtn.disabled = false;
        elements.submitFeedbackBtn.innerHTML = '<i class="fas fa-paper-plane"></i> Submit Feedback';
    }
}

/**
 * Submit feedback to API
 */
async function submitFeedback(correctLabel, comment = '') {
    if (!currentAnalysisResult) {
        throw new Error('No analysis result available');
    }
    
    const response = await fetch(`${API_BASE_URL}/api/feedback`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: currentAnalysisResult.url,
            correct_label: correctLabel,
            user_comment: comment || null
        })
    });
    
    if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || `HTTP ${response.status}`);
    }
    
    const result = await response.json();
    console.log('Feedback submitted:', result);
    showToast('Feedback submitted successfully!', 'success');
    
    return result;
}

/**
 * Check API status
 */
async function checkApiStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/health`);
        
        if (response.ok) {
            const status = await response.json();
            updateApiStatus(true, 'API Online');
        } else {
            updateApiStatus(false, 'API Error');
        }
    } catch (error) {
        updateApiStatus(false, 'API Offline');
    }
}

/**
 * Update API status indicator
 */
function updateApiStatus(isOnline, statusText) {
    if (isOnline) {
        elements.statusIndicator.classList.remove('offline');
        elements.statusText.textContent = statusText;
    } else {
        elements.statusIndicator.classList.add('offline');
        elements.statusText.textContent = statusText;
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info', duration = 4000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    // Add to container
    elements.toastContainer.appendChild(toast);
    
    // Auto remove
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, duration);
}

/**
 * Get toast container element
 */
Object.defineProperty(elements, 'toastContainer', {
    get: function() {
        return document.getElementById('toast-container');
    }
});

/**
 * Utility function to format numbers
 */
function formatNumber(number, decimals = 1) {
    return Number(number).toFixed(decimals);
}

/**
 * Utility function to truncate text
 */
function truncateText(text, maxLength = 50) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showToast('Copied to clipboard!', 'success');
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        showToast('Failed to copy to clipboard', 'error');
    }
}

// Add click-to-copy functionality for URLs
document.addEventListener('click', function(e) {
    if (e.target.id === 'analyzed-url' && currentAnalysisResult) {
        copyToClipboard(currentAnalysisResult.url);
    }
});

// Periodically check API status
setInterval(checkApiStatus, 30000); // Check every 30 seconds

// Handle page visibility for better performance
document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        // Page is hidden, pause any intensive operations
    } else {
        // Page is visible, resume operations
        checkApiStatus();
    }
});

// Performance monitoring
if ('performance' in window) {
    window.addEventListener('load', function() {
        const loadTime = performance.now();
        console.log(`Page loaded in ${loadTime.toFixed(2)}ms`);
    });
}

// Error boundary for unhandled errors
window.addEventListener('error', function(e) {
    console.error('Unhandled error:', e.error);
    showToast('An unexpected error occurred', 'error');
});

// Initialize app state
let appState = {
    isAnalyzing: false,
    analysisHistory: [],
    feedbackCount: 0
};

// Export functions for testing (if running in Node.js environment)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        handleUrlScan,
        validateInput,
        showToast,
        formatNumber,
        truncateText
    };
}