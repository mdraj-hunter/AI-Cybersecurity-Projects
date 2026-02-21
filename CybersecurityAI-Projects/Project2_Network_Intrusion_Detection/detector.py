"""
Network Intrusion Detection System
Main detection application with ML model
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import pickle
import os


class NetworkIntrusionDetector:
    def __init__(self):
        self.model = None
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = []
        self.is_trained = False
        self.attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
    
    def extract_features(self, packet_data):
        """Extract features from network packet data"""
        features = {}
        
        # Basic features
        features['duration'] = packet_data.get('duration', 0)
        features['protocol_type'] = packet_data.get('protocol_type', 0)
        features['service'] = packet_data.get('service', 0)
        features['flag'] = packet_data.get('flag', 0)
        
        # Byte counts
        features['src_bytes'] = packet_data.get('src_bytes', 0)
        features['dst_bytes'] = packet_data.get('dst_bytes', 0)
        features['total_bytes'] = features['src_bytes'] + features['dst_bytes']
        
        # Packet counts
        features['src_packets'] = packet_data.get('src_packets', 0)
        features['dst_packets'] = packet_data.get('dst_packets', 0)
        features['total_packets'] = features['src_packets'] + features['dst_packets']
        
        # Error rates
        features['serror_rate'] = packet_data.get('serror_rate', 0)
        features['rerror_rate'] = packet_data.get('rerror_rate', 0)
        features['same_srv_rate'] = packet_data.get('same_srv_rate', 0)
        features['diff_srv_rate'] = packet_data.get('diff_srv_rate', 0)
        
        # Connection counts
        features['count'] = packet_data.get('count', 0)
        features['srv_count'] = packet_data.get('srv_count', 0)
        features['serror_count'] = packet_data.get('serror_count', 0)
        features['rerror_count'] = packet_data.get('rerror_count', 0)
        
        # Derived features
        if features['duration'] > 0:
            features['bytes_per_sec'] = features['total_bytes'] / features['duration']
            features['packets_per_sec'] = features['total_packets'] / features['duration']
        else:
            features['bytes_per_sec'] = 0
            features['packets_per_sec'] = 0
        
        # Attack indicators
        features['land'] = packet_data.get('land', 0)
        features['wrong_fragment'] = packet_data.get('wrong_fragment', 0)
        features['urgent'] = packet_data.get('urgent', 0)
        features['hot'] = packet_data.get('hot', 0)
        features['num_failed_logins'] = packet_data.get('num_failed_logins', 0)
        features['logged_in'] = packet_data.get('logged_in', 0)
        features['num_compromised'] = packet_data.get('num_compromised', 0)
        features['su_attempted'] = packet_data.get('su_attempted', 0)
        features['num_root'] = packet_data.get('num_root', 0)
        features['num_file_creations'] = packet_data.get('num_file_creations', 0)
        features['num_shells'] = packet_data.get('num_shells', 0)
        features['num_access_files'] = packet_data.get('num_access_files', 0)
        features['is_guest_login'] = packet_data.get('is_guest_login', 0)
        
        return features
    
    def prepare_features(self, data_list):
        """Convert list of packet data to feature matrix"""
        features_list = []
        for data in data_list:
            features = self.extract_features(data)
            features_list.append(features)
        
        df = pd.DataFrame(features_list)
        self.feature_names = list(df.columns)
        return df
    
    def train(self, X, y):
        """Train the intrusion detection model"""
        X_scaled = self.scaler.fit_transform(X)
        y_encoded = self.label_encoder.fit_transform(y)
        
        # Train classifier
        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled, y_encoded)
        
        # Train anomaly detector on normal traffic
        normal_mask = y == 'normal'
        if normal_mask.sum() > 10:
            self.anomaly_detector = IsolationForest(
                contamination=0.15,
                n_estimators=200,
                random_state=42,
                n_jobs=-1
            )
            self.anomaly_detector.fit(X_scaled[normal_mask])
        
        self.is_trained = True
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_scaled, y_encoded, cv=5, scoring='accuracy')
        print(f"Cross-validation Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        return self
    
    def detect(self, packet_data):
        """Detect intrusion in network data"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        features = self.extract_features(packet_data)
        features_df = pd.DataFrame([features])
        features_scaled = self.scaler.transform(features_df)
        
        # Classification
        prediction_encoded = self.model.predict(features_scaled)[0]
        prediction = self.label_encoder.inverse_transform([prediction_encoded])[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        # Anomaly detection
        is_anomaly = False
        anomaly_score = 0
        if self.anomaly_detector:
            anomaly_result = self.anomaly_detector.predict(features_scaled)[0]
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = anomaly_result == -1
        
        return {
            'is_intrusion': prediction != 'normal' or is_anomaly,
            'attack_type': prediction if prediction != 'normal' else 'anomaly',
            'confidence': float(max(probability)),
            'anomaly_detected': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'severity': self._get_severity(prediction, is_anomaly, anomaly_score)
        }
    
    def _get_severity(self, attack_type, is_anomaly, anomaly_score):
        """Determine severity level"""
        high_severity = ['dos', 'u2r', 'r2l']
        medium_severity = ['probe']
        
        if attack_type in high_severity or (is_anomaly and anomaly_score < -0.5):
            return 'HIGH'
        elif attack_type in medium_severity or (is_anomaly and anomaly_score < -0.2):
            return 'MEDIUM'
        elif is_anomaly:
            return 'LOW'
        else:
            return 'SAFE'
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        X_scaled = self.scaler.transform(X_test)
        y_encoded = self.label_encoder.transform(y_test)
        
        y_pred = self.model.predict(X_scaled)
        
        print("\n" + "="*50)
        print("MODEL EVALUATION")
        print("="*50)
        print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
        print(f"Precision: {precision_score(y_test, y_pred, average='weighted'):.4f}")
        print(f"Recall: {recall_score(y_test, y_pred, average='weighted'):.4f}")
        print(f"F1-Score: {f1_score(y_test, y_pred, average='weighted'):.4f}")
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted')
        }
    
    def save_model(self, filepath='intrusion_model.pkl'):
        """Save model to file"""
        model_data = {
            'model': self.model,
            'anomaly_detector': self.anomaly_detector,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained,
            'attack_types': self.attack_types
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"Model saved to {filepath}")
    
    @classmethod
    def load_model(cls, filepath='intrusion_model.pkl'):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        detector = cls()
        detector.model = model_data['model']
        detector.anomaly_detector = model_data.get('anomaly_detector')
        detector.scaler = model_data['scaler']
        detector.label_encoder = model_data['label_encoder']
        detector.feature_names = model_data['feature_names']
        detector.is_trained = model_data['is_trained']
        detector.attack_types = model_data.get('attack_types', ['normal', 'dos', 'probe', 'r2l', 'u2r'])
        
        return detector


def create_sample_dataset():
    """Create sample dataset for training"""
    np.random.seed(42)
    
    # Normal traffic
    normal_data = []
    for i in range(50):
        normal_data.append({
            'duration': np.random.exponential(10),
            'protocol_type': np.random.choice([1, 2, 3]),
            'service': np.random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            'flag': np.random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            'src_bytes': np.random.exponential(500),
            'dst_bytes': np.random.exponential(800),
            'src_packets': np.random.poisson(5),
            'dst_packets': np.random.poisson(5),
            'serror_rate': np.random.uniform(0, 0.05),
            'rerror_rate': np.random.uniform(0, 0.05),
            'same_srv_rate': np.random.uniform(0.5, 1.0),
            'diff_srv_rate': np.random.uniform(0, 0.3),
            'count': np.random.poisson(5),
            'srv_count': np.random.poisson(5),
            'serror_count': 0,
            'rerror_count': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': np.random.choice([0, 1]),
            'num_compromised': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'is_guest_login': 0,
        })
    
    # DoS attacks
    dos_data = []
    for i in range(30):
        dos_data.append({
            'duration': np.random.exponential(0.5),
            'protocol_type': 1,
            'service': np.random.choice([1, 2, 3]),
            'flag': np.random.choice([1, 2]),
            'src_bytes': np.random.exponential(1000),
            'dst_bytes': np.random.exponential(50),
            'src_packets': np.random.poisson(100),
            'dst_packets': np.random.poisson(1),
            'serror_rate': np.random.uniform(0.8, 1.0),
            'rerror_rate': np.random.uniform(0, 0.1),
            'same_srv_rate': np.random.uniform(0, 0.2),
            'diff_srv_rate': np.random.uniform(0.8, 1.0),
            'count': np.random.poisson(200),
            'srv_count': np.random.poisson(10),
            'serror_count': np.random.poisson(50),
            'rerror_count': 0,
            'land': np.random.choice([0, 1]),
            'wrong_fragment': np.random.poisson(3),
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'is_guest_login': 0,
        })
    
    # Probe attacks
    probe_data = []
    for i in range(25):
        probe_data.append({
            'duration': np.random.exponential(2),
            'protocol_type': np.random.choice([1, 2, 3]),
            'service': np.random.choice([1, 2, 3]),
            'flag': np.random.choice([3, 4, 5]),
            'src_bytes': np.random.exponential(100),
            'dst_bytes': np.random.exponential(200),
            'src_packets': np.random.poisson(20),
            'dst_packets': np.random.poisson(20),
            'serror_rate': np.random.uniform(0.5, 1.0),
            'rerror_rate': np.random.uniform(0, 0.3),
            'same_srv_rate': np.random.uniform(0.1, 0.5),
            'diff_srv_rate': np.random.uniform(0.5, 1.0),
            'count': np.random.poisson(50),
            'srv_count': np.random.poisson(10),
            'serror_count': np.random.poisson(10),
            'rerror_count': np.random.poisson(5),
            'land': 0,
            'wrong_fragment': np.random.poisson(2),
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': np.random.poisson(3),
            'logged_in': 0,
            'num_compromised': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,                            
            'num_access_files': 0,
            'is_guest_login': 0, 
        })
        