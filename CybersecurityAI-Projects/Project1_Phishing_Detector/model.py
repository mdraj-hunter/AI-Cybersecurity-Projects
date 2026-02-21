"""
Phishing Detection Model
Machine Learning model to detect phishing URLs
"""

import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import pickle
import os


class PhishingDetectorModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False
    
    def extract_url_features(self, url):
        """
        Extract features from URL for phishing detection
        Returns a dictionary of features
        """
        features = {}
        
        # URL length features
        features['url_length'] = len(url)
        features['hostname_length'] = len(urlparse(url).netloc) if urlparse(url).netloc else 0
        features['path_length'] = len(urlparse(url).path) if urlparse(url).path else 0
        
        # Count-based features
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_colons'] = url.count(':')
        features['num_semicolons'] = url.count(';')
        features['num_equals'] = url.count('=')
        features['num_ats'] = url.count('@')
        features['num_ampsersands'] = url.count('&')
        features['num_dollars'] = url.count('$')
        features['num_hashtags'] = url.count('#')
        features['num_exclamations'] = url.count('!')
        features['num_tildes'] = url.count('~')
        features['num_backticks'] = url.count('`')
        features['num_quotes'] = url.count('"') + url.count("'")
        features['num_brackets'] = url.count('(') + url.count(')') + url.count('[') + url.count(']')
        
        # Protocol features
        features['has_https'] = 1 if url.startswith('https') else 0
        features['has_http'] = 1 if url.startswith('http') else 0
        
        # IP address feature
        ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        features['has_ip'] = 1 if re.match(ip_pattern, url) else 0
        
        # Domain features
        parsed = urlparse(url)
        domain = parsed.netloc
        
        features['num_subdomains'] = 0
        if domain:
            parts = domain.split('.')
            features['num_subdomains'] = max(0, len(parts) - 2)
            features['has_port'] = 1 if ':' in domain else 0
        
        # Suspicious patterns
        features['has_suspicious_words'] = 0
        suspicious_words = ['secure', 'login', 'signin', 'verify', 'account', 'update', 
                          'confirm', 'banking', 'paypal', 'ebay', 'amazon', 'alert']
        url_lower = url.lower()
        for word in suspicious_words:
            if word in url_lower:
                features['has_suspicious_words'] = 1
                break
        
        # Redirect features
        features['has_redirect'] = 1 if 'redirect' in url_lower else 0
        features['has_url_param'] = 1 if '?' in url else 0
        
        # Entropy calculation (randomness in URL)
        features['entropy'] = self._calculate_entropy(url)
        
        # Special patterns
        features['has_double_extension'] = 1 if re.search(r'\.[a-z]{2,4}\.[a-z]{2,4}', url) else 0
        features['has_punycode'] = 1 if 'xn--' in url else 0
        
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * np.log2(p) for p in prob if p > 0)
    
    def prepare_features(self, urls):
        """Convert list of URLs to feature matrix"""
        features_list = []
        for url in urls:
            features = self.extract_url_features(url)
            features_list.append(features)
        
        df = pd.DataFrame(features_list)
        self.feature_names = list(df.columns)
        return df
    
    def train(self, X, y):
        """Train the phishing detection model"""
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_scaled, y, cv=5, scoring='accuracy')
        print(f"Cross-validation Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        return self
    
    def predict(self, url):
        """Predict if a URL is phishing"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        features = self.extract_url_features(url)
        features_df = pd.DataFrame([features])
        features_scaled = self.scaler.transform(features_df)
        
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        return {
            'url': url,
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'phishing_probability': float(probability[1]),
            'legitimate_probability': float(probability[0]),
            'risk_level': self._get_risk_level(probability[1])
        }
    
    def _get_risk_level(self, phishing_prob):
        """Get risk level based on phishing probability"""
        if phishing_prob >= 0.8:
            return 'CRITICAL'
        elif phishing_prob >= 0.6:
            return 'HIGH'
        elif phishing_prob >= 0.4:
            return 'MEDIUM'
        elif phishing_prob >= 0.2:
            return 'LOW'
        else:
            return 'SAFE'
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        X_scaled = self.scaler.transform(X_test)
        y_pred = self.model.predict(X_scaled)
        
        print("\n" + "="*50)
        print("MODEL EVALUATION")
        print("="*50)
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(f"Precision: {precision_score(y_test, y_pred):.4f}")
        print(f"Recall: {recall_score(y_test, y_pred):.4f}")
        print(f"F1-Score: {f1_score(y_test, y_pred):.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred),
            'recall': recall_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred)
        }
    
    def save_model(self, filepath='phishing_model.pkl'):
        """Save model to file"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {filepath}")
    
    @classmethod
    def load_model(cls, filepath='phishing_model.pkl'):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        detector = cls()
        detector.model = model_data['model']
        detector.scaler = model_data['scaler']
        detector.feature_names = model_data['feature_names']
        detector.is_trained = model_data['is_trained']
        
        return detector


def create_sample_dataset():
    """Create a sample dataset for training"""
    # Legitimate URLs
    legitimate_urls = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'https://www.twitter.com',
        'https://www.linkedin.com',
        'https://www.github.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'https://www.netflix.com',
        'https://www.instagram.com',
        'https://www.reddit.com',
        'https://www.wikipedia.org',
        'https://www.paypal.com',
        'https://www.dropbox.com',
        'https://www.slack.com',
        'https://www.spotify.com',
        'https://www.zoom.us',
        'https://www.shopify.com',
        'https://www.salesforce.com',
        'https://www.adobe.com',
        'https://mail.google.com',
        'docs.google.com',
        'drive.google.com',
        'calendar.google.com',
        'maps.google.com',
        'translate.google.com',
        'news.google.com',
        'photos.google.com',
        'support.google.com',
        'cloud.google.com',
    ]
    
    # Phishing URLs (simulated patterns)
    phishing_urls = [
        'http://192.168.1.1/login.php',
        'https://google.com.secure-login.ru/auth',
        'http://paypal.com.verify-account.xyz/login',
        'https://amazon.com.account-update.ru/billing',
        'http://facebook.com.login.secure-server.eu/',
        'https://microsoft.com.support-login.net/auth',
        'http://192.168.1.100:8080/admin/login',
        'https://login.bankofamerica.com.secure-verify.ru/',
        'http://10.0.0.1/admin',
        'https://account-update.paypal.com.secure-connection.ru/',
        'http://172.16.0.1/login',
        'https://signin.ebay.com.account-verify.ru/',
        'http://192.168.0.1/admin.php',
        'https://apple.com.id-verify.ru/login',
        'http://login.microsoftonline.com.suspicious.ru/',
        'https://netflix.com.payment-verify.ru/',
        'http://www.google.com.malware-site.ru/',
        'https://dropbox.com.verify-login.ru/auth',
        'http://instagram.com.hacker-site.net/login',
        'https://github.com.secure-login.in/auth',
    ]
    
    # Create dataset
    urls = legitimate_urls + phishing_urls
    labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    return urls, labels


if __name__ == "__main__":
    print("="*60)
    print("PHISHING DETECTION MODEL - TRAINING")
    print("="*60)
    
    # Create sample dataset
    print("\n1. Creating sample dataset...")
    urls, labels = create_sample_dataset()
    print(f"   Total samples: {len(urls)}")
    num_legit = labels.count(0)
    num_phish = labels.count(1)
    print(f"   Legitimate: {num_legit}, Phishing: {num_phish}")
    
    # Initialize model
    detector = PhishingDetectorModel()
    
    # Extract features
    print("\n2. Extracting features...")
    X = detector.prepare_features(urls)
    y = labels
    print(f"   Features extracted: {len(detector.feature_names)}")
    
    # Split data
    print("\n3. Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Testing samples: {len(X_test)}")
    
    # Train model
    print("\n4. Training model...")
    detector.train(X_train, y_train)
    
    # Evaluate model
    print("\n5. Evaluating model...")
    metrics = detector.evaluate(X_test, y_test)
    
    # Save model
    print("\n6. Saving model...")
    detector.save_model('phishing_model.pkl')
    
    # Test predictions
    print("\n" + "="*60)
    print("TEST PREDICTIONS")
    print("="*60)
    
    test_urls = [
        'https://www.google.com',
        'https://paypal.com.verify-account.ru/login',
        'https://github.com',
        'http://192.168.1.1/admin',
        'https://www.microsoft.com',
    ]
    
    for url in test_urls:
        result = detector.predict(url)
        print(f"\nURL: {url}")
        print(f"   Is Phishing: {result['is_phishing']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Risk Level: {result['risk_level']}")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    if __name__ == "__main__":
     print("="*60)
    print("PHISHING DETECTION MODEL - TRAINING")
    print("="*60)
    
    # Create sample dataset
    print("\n1. Creating sample dataset...")
    urls, labels = create_sample_dataset()
    
    # Get counts for reporting
    num_legit = labels.count(0)
    num_phish = labels.count(1)
    
    print(f"   Total samples: {len(urls)}")
    print(f"   Legitimate: {num_legit}, Phishing: {num_phish}")
    
    # Initialize model
    detector = PhishingDetectorModel()
    
    # Extract features
    print("\n2. Extracting features...")
    X = detector.prepare_features(urls)
    y = labels
    print(f"   Features extracted: {len(detector.feature_names)}")
    
    # Split data
    print("\n3. Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"   Training samples: {len(X_train)}")
    print(f"   Testing samples: {len(X_test)}")
    
    # Train model
    print("\n4. Training model...")
    detector.train(X_train, y_train)
    
    # Evaluate model
    print("\n5. Evaluating model...")
    metrics = detector.evaluate(X_test, y_test)
    
    # Save model
    print("\n6. Saving model...")
    detector.save_model('phishing_model.pkl')
    
    # Test predictions
    print("\n" + "="*60)
    print("TEST PREDICTIONS")
    print("="*60)
    
    test_urls = [
        'https://www.google.com',
        'https://paypal.com.verify-account.ru/login',
        'https://github.com',
        'http://192.168.1.1/admin',
        'https://www.microsoft.com',
    ]
    
    for url in test_urls:
        result = detector.predict(url)
        print(f"\nURL: {url}")
        print(f"   Is Phishing: {result['is_phishing']}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Risk Level: {result['risk_level']}")
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)