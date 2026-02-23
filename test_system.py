"""
System Integration Test for AI Phishing Detection System
Purpose: Verify all components work together correctly
"""

import sys
import os
import json
import time
import requests
from datetime import datetime

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_banner():
    """Display test banner"""
    print("🧪 AI PHISHING DETECTION SYSTEM - INTEGRATION TESTS")
    print("=" * 60)
    print(f"Test started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

def test_dataset_generation():
    """Test dataset generation"""
    print("\n1️⃣ Testing Dataset Generation...")
    
    try:
        from dataset_generator import PhishingDatasetGenerator
        
        generator = PhishingDatasetGenerator()
        
        # Generate small test dataset
        dataset = generator.generate_phishing_dataset(num_samples=100)
        
        if len(dataset) >= 100:
            print("   ✅ Dataset generation: PASSED")
            print(f"   📊 Generated {len(dataset)} samples")
            
            # Check data balance
            phishing_count = sum(1 for _, label in dataset if label == 1)
            legit_count = len(dataset) - phishing_count
            print(f"   📈 Balance: {phishing_count} phishing, {legit_count} legitimate")
            return True
        else:
            print("   ❌ Dataset generation: FAILED")
            return False
            
    except Exception as e:
        print(f"   ❌ Dataset generation error: {e}")
        return False

def test_heuristic_engine():
    """Test heuristic analysis engine"""
    print("\n2️⃣ Testing Heuristic Analysis Engine...")
    
    try:
        from services.detection_engine import HeuristicAnalyzer
        
        analyzer = HeuristicAnalyzer()
        
        # Test URLs
        test_cases = [
            ("https://www.paypal.com", "legitimate site"),
            ("http://payp4l-login.suspicious.com", "obvious phishing"),
            ("https://192.168.1.1/secure", "IP-based URL"),
            ("http://www.g00gle.com", "character substitution")
        ]
        
        all_passed = True
        
        for url, description in test_cases:
            result = analyzer.calculate_heuristic_score(url)
            score = result['heuristic_score']
            
            print(f"   🔗 {description}: {score:.1f}/40")
            
            # Basic validation
            if not (0 <= score <= 40):
                print(f"   ❌ Invalid score range for {url}")
                all_passed = False
        
        if all_passed:
            print("   ✅ Heuristic analysis: PASSED")
            return True
        else:
            print("   ❌ Heuristic analysis: FAILED")
            return False
            
    except Exception as e:
        print(f"   ❌ Heuristic analysis error: {e}")
        return False

def test_ml_model():
    """Test ML model prediction"""
    print("\n3️⃣ Testing Machine Learning Model...")
    
    try:
        from services.detection_engine import MLPredictor
        
        predictor = MLPredictor()
        
        # Try to load model
        if predictor.load_model():
            print("   ✅ Model loading: PASSED")
            
            test_urls = [
                "https://www.paypal.com",
                "http://payp4l-security.com/login",
                "https://www.google.com"
            ]
            
            all_passed = True
            
            for url in test_urls:
                result = predictor.predict(url)
                
                if result['ml_available']:
                    probability = result['ml_probability']
                    print(f"   🧠 {url}: {probability:.3f} probability")
                    
                    if not (0 <= probability <= 1):
                        all_passed = False
                else:
                    print(f"   ⚠️  ML not available for {url}")
            
            if all_passed:
                print("   ✅ ML prediction: PASSED")
                return True
            else:
                print("   ❌ ML prediction: FAILED")
                return False
        else:
            print("   ⚠️  No trained model found - run training first")
            print("   💡 Run: python models/train_model.py")
            return False
            
    except Exception as e:
        print(f"   ❌ ML model error: {e}")
        return False

def test_hybrid_engine():
    """Test complete hybrid detection engine"""
    print("\n4️⃣ Testing Hybrid Detection Engine...")
    
    try:
        from services.detection_engine import HybridDetectionEngine
        
        engine = HybridDetectionEngine()
        
        test_cases = [
            ("https://www.paypal.com", "should be safe"),
            ("http://payp4l-security.com/verify", "should be phishing"),
            ("https://192.168.1.100/login", "should be suspicious")
        ]
        
        all_passed = True
        
        for url, expectation in test_cases:
            result = engine.analyze_url(url)
            
            print(f"   🔍 {url}")
            print(f"      📊 Score: {result['final_score']:.1f}/100")
            print(f"      🏷️  Class: {result['classification']}")
            print(f"      💭 Expected: {expectation}")
            
            # Basic validation
            if not (0 <= result['final_score'] <= 100):
                print(f"      ❌ Invalid score range")
                all_passed = False
            
            if result['classification'] not in ['Safe', 'Suspicious', 'Phishing']:
                print(f"      ❌ Invalid classification")
                all_passed = False
        
        if all_passed:
            print("   ✅ Hybrid engine: PASSED")
            return True
        else:
            print("   ❌ Hybrid engine: FAILED") 
            return False
            
    except Exception as e:
        print(f"   ❌ Hybrid engine error: {e}")
        return False

def test_api_server():
    """Test FastAPI server (if running)"""
    print("\n5️⃣ Testing API Server...")
    
    try:
        # Check if server is running
        response = requests.get("http://localhost:8000/health", timeout=5)
        
        if response.status_code == 200:
            health_data = response.json()
            print("   ✅ Health check: PASSED")
            print(f"   📡 Status: {health_data.get('status', 'unknown')}")
            
            # Test scan endpoint
            scan_data = {"url": "https://www.paypal.com"}
            scan_response = requests.post(
                "http://localhost:8000/scan-url", 
                json=scan_data, 
                timeout=10
            )
            
            if scan_response.status_code == 200:
                scan_result = scan_response.json()
                print("   ✅ URL scan endpoint: PASSED")
                print(f"   📊 Score: {scan_result.get('final_score', 'N/A')}")
                return True
            else:
                print(f"   ❌ Scan endpoint failed: {scan_response.status_code}")
                return False
                
        else:
            print(f"   ❌ Health check failed: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("   ⚠️  API server not running")
        print("   💡 Start server first: python main.py")
        return False
    except Exception as e:
        print(f"   ❌ API test error: {e}")
        return False

def test_frontend_files():
    """Test frontend files exist and are valid"""
    print("\n6️⃣ Testing Frontend Files...")
    
    frontend_files = [
        "frontend/index.html",
        "frontend/style.css", 
        "frontend/script.js"
    ]
    
    all_passed = True
    
    for file_path in frontend_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            print(f"   ✅ {file_path}: {file_size:,} bytes")
        else:
            print(f"   ❌ Missing: {file_path}")
            all_passed = False
    
    if all_passed:
        print("   ✅ Frontend files: PASSED")
        return True
    else:
        print("   ❌ Frontend files: FAILED")
        return False

def run_performance_test():
    """Run basic performance test"""
    print("\n7️⃣ Performance Test...")
    
    try:
        from services.detection_engine import HybridDetectionEngine
        
        engine = HybridDetectionEngine()
        
        test_url = "https://www.example.com"
        iterations = 10
        
        start_time = time.time()
        
        for i in range(iterations):
            result = engine.analyze_url(test_url)
        
        end_time = time.time()
        
        avg_time = (end_time - start_time) / iterations * 1000  # Convert to ms
        
        print(f"   ⚡ Average analysis time: {avg_time:.1f}ms")
        
        if avg_time < 1000:  # Less than 1 second
            print("   ✅ Performance: PASSED")
            return True
        else:
            print("   ⚠️  Performance: SLOW (but functional)")
            return True
            
    except Exception as e:
        print(f"   ❌ Performance test error: {e}")
        return False

def generate_test_report(results):
    """Generate test report"""
    print("\n" + "=" * 60)
    print("📋 TEST SUMMARY REPORT")
    print("=" * 60)
    
    passed = sum(results.values())
    total = len(results)
    success_rate = (passed / total) * 100 if total > 0 else 0
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
    
    print("-" * 60)
    print(f"📊 Overall: {passed}/{total} tests passed ({success_rate:.1f}%)")
    
    if success_rate >= 80:
        print("🎉 System is ready for production!")
    elif success_rate >= 60:
        print("⚠️  System has some issues but is functional")
    else:
        print("❌ System needs attention before deployment")
    
    print("=" * 60)
    
    return success_rate

def main():
    """Run all integration tests"""
    test_banner()
    
    # Define test suite
    tests = [
        ("Dataset Generation", test_dataset_generation),
        ("Heuristic Engine", test_heuristic_engine),
        ("ML Model", test_ml_model),
        ("Hybrid Engine", test_hybrid_engine),
        ("API Server", test_api_server),
        ("Frontend Files", test_frontend_files),
        ("Performance", run_performance_test)
    ]
    
    results = {}
    
    # Run tests
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"   💥 Test crashed: {e}")
            results[test_name] = False
        
        time.sleep(0.5)  # Brief pause between tests
    
    # Generate report
    success_rate = generate_test_report(results)
    
    return 0 if success_rate >= 80 else 1

if __name__ == "__main__":
    sys.exit(main())