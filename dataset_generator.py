"""
Automatic Dataset Generator for Phishing URL Detection
Purpose: Generate spoofed URLs and clean datasets automatically
"""

import csv
import random
import string
import itertools
from typing import List, Tuple
import os
from datetime import datetime

class PhishingDatasetGenerator:
    def __init__(self):
        """Initialize the dataset generator with brand names and attack patterns"""
        self.top_brands = [
            'paypal', 'google', 'amazon', 'microsoft', 'apple', 
            'facebook', 'netflix', 'instagram', 'twitter', 'linkedin',
            'github', 'dropbox', 'adobe', 'yahoo', 'ebay'
        ]
        
        self.tlds = ['.com', '.net', '.org', '.info', '.biz', '.co', '.io', '.ly']
        self.suspicious_subdomains = [
            'secure', 'login', 'verify', 'update', 'support', 'account',
            'security', 'confirm', 'validation', 'auth', 'signin'
        ]
        
        # Character substitution mappings for spoofing
        self.char_substitutions = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!', 'l'],
            'o': ['0'],
            'l': ['1', '!', 'i'],
            'g': ['9'],
            's': ['5', '$'],
            't': ['7']
        }
        
        # Homoglyph attacks (visually similar characters)
        self.homoglyphs = {
            'a': ['а', 'ɑ'],  # Cyrillic 'a'
            'o': ['о', 'ο'],  # Cyrillic 'o', Greek omicron
            'p': ['р'],       # Cyrillic 'p'
            'e': ['е'],       # Cyrillic 'e'
            'c': ['с'],       # Cyrillic 'c'
        }

    def generate_character_swaps(self, domain: str) -> List[str]:
        """Generate character substitution variants"""
        variants = []
        
        for char, substitutes in self.char_substitutions.items():
            if char in domain:
                for substitute in substitutes:
                    variants.append(domain.replace(char, substitute))
        
        return variants

    def generate_case_manipulation(self, domain: str) -> List[str]:
        """Generate case manipulation variants"""
        variants = []
        
        # Mixed case patterns
        variants.append(''.join(c.upper() if i % 2 == 0 else c for i, c in enumerate(domain)))
        variants.append(''.join(c.upper() if i % 2 == 1 else c for i, c in enumerate(domain)))
        
        # Random case changes (2-3 variants)
        for _ in range(2):
            variant = ''.join(c.upper() if random.random() > 0.7 else c for c in domain)
            variants.append(variant)
            
        return variants

    def generate_homoglyph_attacks(self, domain: str) -> List[str]:
        """Generate homoglyph substitution variants"""
        variants = []
        
        for char, homoglyphs in self.homoglyphs.items():
            if char in domain:
                for homoglyph in homoglyphs:
                    variants.append(domain.replace(char, homoglyph))
        
        return variants

    def generate_hyphen_variants(self, domain: str) -> List[str]:
        """Generate extra hyphen variants"""
        variants = []
        
        # Insert hyphens at various positions
        for i in range(1, len(domain)):
            variants.append(domain[:i] + '-' + domain[i:])
        
        # Multiple hyphens
        variants.append(domain.replace('a', 'a-'))
        variants.append(domain.replace('e', 'e-'))
        
        return variants[:5]  # Limit to 5 variants

    def generate_subdomain_tricks(self, brand: str) -> List[str]:
        """Generate subdomain-based phishing URLs"""
        variants = []
        
        fake_domains = [
            'security-center.com', 'login-verify.net', 'account-update.org',
            'secure-bank.com', 'verification-service.net', 'update-center.info'
        ]
        
        for subdomain in self.suspicious_subdomains:
            for fake_domain in fake_domains[:3]:
                variants.append(f"{brand}.{subdomain}-{fake_domain}")
                variants.append(f"{subdomain}-{brand}.{fake_domain}")
        
        return variants

    def generate_ip_based_urls(self) -> List[str]:
        """Generate suspicious IP-based URLs"""
        variants = []
        
        # Generate realistic-looking IP addresses
        for _ in range(5):
            ip = f"{random.randint(192, 223)}.{random.randint(168, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            variants.append(f"http://{ip}/login")
            variants.append(f"https://{ip}/secure/account")
        
        return variants

    def generate_typosquatting(self, domain: str) -> List[str]:
        """Generate typosquatting variants"""
        variants = []
        
        # Character omission
        for i in range(len(domain)):
            if len(domain) > 3:
                variants.append(domain[:i] + domain[i+1:])
        
        # Character insertion
        for i in range(len(domain) + 1):
            char = random.choice(string.ascii_lowercase)
            variants.append(domain[:i] + char + domain[i:])
        
        # Character transposition
        for i in range(len(domain) - 1):
            chars = list(domain)
            chars[i], chars[i+1] = chars[i+1], chars[i]
            variants.append(''.join(chars))
        
        return variants[:8]  # Limit variants

    def generate_legitimate_urls(self) -> List[str]:
        """Generate legitimate URLs for the safe class"""
        legitimate_urls = []
        
        # Real brand URLs
        for brand in self.top_brands:
            legitimate_urls.append(f"https://www.{brand}.com")
            legitimate_urls.append(f"https://{brand}.com/login")
            legitimate_urls.append(f"https://secure.{brand}.com")
        
        # Other legitimate sites
        legit_sites = [
            'wikipedia.org', 'stackoverflow.com', 'github.com', 'medium.com',
            'reddit.com', 'youtube.com', 'news.ycombinator.com', 'bbc.co.uk'
        ]
        
        for site in legit_sites:
            legitimate_urls.append(f"https://www.{site}")
            legitimate_urls.append(f"https://{site}/article/sample")
        
        return legitimate_urls

    def generate_phishing_dataset(self, num_samples: int = 5000) -> List[Tuple[str, int]]:
        """Generate complete phishing dataset"""
        dataset = []
        
        print(f"Generating {num_samples} phishing samples...")
        
        # Generate phishing URLs (label = 1)
        phishing_count = 0
        target_phishing = num_samples // 2
        
        for brand in self.top_brands:
            if phishing_count >= target_phishing:
                break
                
            # Character swaps
            for url in self.generate_character_swaps(brand)[:3]:
                dataset.append((f"https://www.{url}.com", 1))
                phishing_count += 1
            
            # Case manipulation
            for url in self.generate_case_manipulation(brand)[:2]:
                dataset.append((f"https://www.{url}.com", 1))
                phishing_count += 1
            
            # Homoglyph attacks
            for url in self.generate_homoglyph_attacks(brand)[:2]:
                dataset.append((f"https://www.{url}.com", 1))
                phishing_count += 1
            
            # Hyphen variants
            for url in self.generate_hyphen_variants(brand)[:2]:
                dataset.append((f"https://www.{url}.com", 1))
                phishing_count += 1
            
            # Subdomain tricks
            for url in self.generate_subdomain_tricks(brand)[:3]:
                dataset.append((f"https://{url}", 1))
                phishing_count += 1
            
            # Typosquatting
            for url in self.generate_typosquatting(brand)[:3]:
                dataset.append((f"https://www.{url}.com", 1))
                phishing_count += 1
        
        # Add IP-based URLs
        for url in self.generate_ip_based_urls():
            dataset.append((url, 1))
            phishing_count += 1
        
        print(f"Generated {phishing_count} phishing URLs")
        
        # Generate legitimate URLs (label = 0)  
        legitimate_urls = self.generate_legitimate_urls()
        legit_count = 0
        target_legit = num_samples - phishing_count
        
        for url in legitimate_urls:
            if legit_count >= target_legit:
                break
            dataset.append((url, 0))
            legit_count += 1
        
        # Add more random legitimate variations if needed
        while legit_count < target_legit:
            brand = random.choice(self.top_brands)
            tld = random.choice(self.tlds)
            url = f"https://www.{brand}{tld}"
            dataset.append((url, 0))
            legit_count += 1
        
        print(f"Generated {legit_count} legitimate URLs")
        
        # Shuffle the dataset
        random.shuffle(dataset)
        return dataset

    def save_dataset(self, dataset: List[Tuple[str, int]], filename: str = None):
        """Save dataset to CSV file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data/generated_dataset_{timestamp}.csv"
        
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['url', 'label'])  # Header
            writer.writerows(dataset)
        
        print(f"Dataset saved to {filename}")
        return filename

def main():
    """Main function to generate and save dataset"""
    generator = PhishingDatasetGenerator()
    
    print("🚀 Starting Phishing Dataset Generation...")
    print("=" * 50)
    
    # Generate dataset
    dataset = generator.generate_phishing_dataset(num_samples=5000)
    
    # Save to default location
    filename = generator.save_dataset(dataset, "data/generated_dataset.csv")
    
    # Print statistics
    phishing_count = sum(1 for _, label in dataset if label == 1)
    legit_count = len(dataset) - phishing_count
    
    print("\n📊 Dataset Statistics:")
    print(f"Total URLs: {len(dataset)}")
    print(f"Phishing URLs: {phishing_count}")
    print(f"Legitimate URLs: {legit_count}")
    print(f"Balance ratio: {phishing_count/len(dataset):.2%} phishing")
    print("\n✅ Dataset generation complete!")

if __name__ == "__main__":
    main()