# 🛡️ AI Phishing Detection System

> **Deployment Ready**: Advanced Deep Learning + Heuristic Hybrid Phishing URL Detection System

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.15+-orange?style=for-the-badge&logo=tensorflow)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green?style=for-the-badge&logo=fastapi)
![Vercel](https://img.shields.io/badge/Vercel-Ready-black?style=for-the-badge&logo=vercel)

## 🏗️ Repository Structure  

```
URL-Phising/
├── 📁 api/              # Vercel serverless functions
├── 📁 frontend/         # Web interface (HTML/CSS/JS)
├── 📁 services/         # Core detection engine  
├── 📁 models/           # ML training scripts
├── main.py             # Local development server
├── requirements.txt    # Dependencies
└── vercel.json         # Vercel deployment config
```

## 🚀 **System Features**

Production-ready AI phishing detection system featuring:

- **🧠 Deep Learning Models** - Bidirectional LSTM with character-level tokenization
- **🔍 Heuristic Rule Engine** - Pattern analysis, URL structure analysis 
- **🌐 Real-time Threat Intelligence** - VirusTotal API integration
- **📊 Risk Scoring System** - 0-100 comprehensive risk assessment
- **🔄 Adaptive Learning** - Feedback loop with automatic model retraining
- **⚡ FastAPI Backend** - RESTful API with async processing  
- **💻 Modern Frontend** - Responsive HTML/CSS/JS interface

## 🎯 **Detection Capabilities**

### **AI Detection Engine**
- Character-level deep learning analysis
- Bidirectional LSTM neural network
- Real-time URL feature extraction
- Pattern recognition for spoofed domains

### **Heuristic Analysis** 
- Brand spoofing detection (PayPal, Google, Amazon, Microsoft, etc.)
- Character substitution attacks (o→0, l→1, i→1)
- Homoglyph attacks (Cyrillic characters)
- Subdomain manipulation detection
- IP-based phishing URL identification

### **API Integration**
- VirusTotal threat intelligence
- Real-time reputation checking
- Multi-engine malware scanning
- Comprehensive risk assessment

## 🚀 **Quick Deploy**

### **Vercel Deployment (Recommended)**

1. **Clone repository**
   ```bash
   git clone https://github.com/devaanshkushwaha06/URL-Phishing-Checker.git
   cd URL-Phishing-Checker
   ```

2. **Deploy to Vercel**
   ```bash
   npm i -g vercel
   vercel
   ```

3. **Configure Environment Variables** (Optional)
   - Add `VIRUSTOTAL_API_KEY` for enhanced detection
   - Add admin credentials for dashboard access

4. **Access Application**
   - Main interface: `https://your-app.vercel.app/`
   - API docs: `https://your-app.vercel.app/api/docs`

### **Local Development**

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run Development Server**
   ```bash
   python main.py
   ```

3. **Access Locally**
   - Main app: `http://localhost:8000`
   - API docs: `http://localhost:8000/docs`

## 🔗 **API Endpoints**

- `POST /scan` - Analyze URL for phishing
- `POST /feedback` - Submit user feedback  
- `GET /stats` - Get system statistics
- `GET /admin/dashboard` - Admin interface
- `POST /admin/login` - Admin authentication

## 📊 **Response Format**

```json
{
  "success": true,
  "url": "https://example.com",
  "classification": "legitimate",
  "risk_level": "low", 
  "final_score": 15.2,
  "deep_learning_probability": 0.12,
  "heuristic_score": 8.5,
  "api_score": 0,
  "explanation": "URL appears legitimate with no suspicious patterns detected"
}
```

## 🛡️ **Security Features**

- Input validation and sanitization
- Rate limiting protection  
- Admin authentication system
- Secure API endpoints
- Data privacy compliance

## 🔧 **Technical Stack**

- **Backend**: FastAPI (Python)
- **AI/ML**: TensorFlow, NumPy, Pandas
- **Frontend**: HTML5, CSS3, JavaScript
- **Deployment**: Vercel (Serverless)
- **APIs**: VirusTotal integration

## 📝 **License**

MIT License - See LICENSE file for details

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)  
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

**🚀 Ready to deploy!** This repository contains only production-ready code without configuration files or sensitive data.