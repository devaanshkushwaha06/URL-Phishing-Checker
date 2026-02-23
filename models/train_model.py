"""
Deep Learning Model Trainer for Phishing URL Detection
Purpose: Character-level LSTM model with binary classification
"""

import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout, Bidirectional
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os
import json
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns

class PhishingModelTrainer:
    def __init__(self, max_url_length: int = 200, vocab_size: int = 10000):
        """
        Initialize the model trainer
        
        Args:
            max_url_length: Maximum length of URL for padding
            vocab_size: Maximum vocabulary size for tokenizer
        """
        self.max_url_length = max_url_length
        self.vocab_size = vocab_size
        self.tokenizer = None
        self.model = None
        self.history = None
        
    def preprocess_urls(self, urls: list) -> np.ndarray:
        """
        Preprocess URLs for character-level tokenization
        
        Args:
            urls: List of URLs
            
        Returns:
            Padded sequences ready for model input
        """
        # Convert URLs to character sequences
        char_sequences = []
        for url in urls:
            # Convert URL to character sequence
            chars = [c for c in url.lower() if c.isprintable()]
            char_sequences.append(' '.join(chars))
        
        # Create tokenizer if not exists
        if self.tokenizer is None:
            self.tokenizer = Tokenizer(
                num_words=self.vocab_size,
                char_level=False,  # We'll handle character level manually
                oov_token='<OOV>'
            )
            self.tokenizer.fit_on_texts(char_sequences)
        
        # Convert to sequences
        sequences = self.tokenizer.texts_to_sequences(char_sequences)
        
        # Pad sequences
        padded_sequences = pad_sequences(
            sequences, 
            maxlen=self.max_url_length, 
            padding='post',
            truncating='post'
        )
        
        return padded_sequences
    
    def create_model(self) -> Sequential:
        """
        Create Bidirectional LSTM model for phishing detection
        
        Returns:
            Compiled Keras model
        """
        model = Sequential([
            # Embedding layer
            Embedding(
                input_dim=self.vocab_size,
                output_dim=128,
                input_length=self.max_url_length,
                mask_zero=True
            ),
            
            # Bidirectional LSTM layers
            Bidirectional(LSTM(64, return_sequences=True, dropout=0.3)),
            Bidirectional(LSTM(32, dropout=0.3)),
            
            # Dense layers
            Dense(64, activation='relu'),
            Dropout(0.4),
            Dense(32, activation='relu'),
            Dropout(0.3),
            
            # Output layer
            Dense(1, activation='sigmoid')
        ])
        
        # Compile model
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        return model
    
    def train_model(self, dataset_path: str, validation_split: float = 0.2, epochs: int = 50):
        """
        Train the phishing detection model
        
        Args:
            dataset_path: Path to the CSV dataset
            validation_split: Fraction of data for validation
            epochs: Number of training epochs
        """
        print("🔄 Loading dataset...")
        
        # Load dataset
        df = pd.read_csv(dataset_path)
        print(f"Dataset loaded: {len(df)} samples")
        
        # Prepare data
        urls = df['url'].tolist()
        labels = df['label'].values
        
        # Preprocess URLs
        print("🔄 Preprocessing URLs...")
        X = self.preprocess_urls(urls)
        y = labels
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training samples: {len(X_train)}")
        print(f"Testing samples: {len(X_test)}")
        
        # Create model
        print("🔄 Creating model...")
        self.model = self.create_model()
        
        # Print model summary
        print("\n📋 Model Architecture:")
        self.model.summary()
        
        # Callbacks
        callbacks = [
            tf.keras.callbacks.EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-7
            )
        ]
        
        # Train model
        print("\n🚀 Starting training...")
        self.history = self.model.fit(
            X_train, y_train,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=32,
            callbacks=callbacks,
            verbose=1
        )
        
        # Evaluate on test set
        print("\n📊 Evaluating model...")
        test_loss, test_accuracy, test_precision, test_recall = self.model.evaluate(X_test, y_test, verbose=0)
        
        print(f"Test Accuracy: {test_accuracy:.4f}")
        print(f"Test Precision: {test_precision:.4f}")
        print(f"Test Recall: {test_recall:.4f}")
        
        # Predictions for detailed metrics
        y_pred = (self.model.predict(X_test) > 0.5).astype(int)
        
        print("\n📈 Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Save training metrics
        self.save_training_metrics(test_accuracy, test_precision, test_recall)
        
        return self.history
    
    def save_model(self, model_path: str = None) -> str:
        """
        Save the trained model and tokenizer
        
        Args:
            model_path: Path to save model (if None, auto-generate)
            
        Returns:
            Path where model was saved
        """
        if model_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_path = f"models/phishing_model_{timestamp}"
        
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model
        self.model.save(f"{model_path}.h5")
        
        # Save tokenizer
        with open(f"{model_path}_tokenizer.pkl", 'wb') as f:
            pickle.dump(self.tokenizer, f)
        
        # Save metadata
        metadata = {
            'model_path': f"{model_path}.h5",
            'tokenizer_path': f"{model_path}_tokenizer.pkl",
            'max_url_length': self.max_url_length,
            'vocab_size': self.vocab_size,
            'timestamp': datetime.now().isoformat(),
            'model_type': 'Bidirectional LSTM'
        }
        
        with open(f"{model_path}_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✅ Model saved to {model_path}")
        return model_path
    
    def save_training_metrics(self, accuracy: float, precision: float, recall: float):
        """Save training metrics to file"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'test_accuracy': float(accuracy),
            'test_precision': float(precision),
            'test_recall': float(recall),
            'f1_score': float(2 * (precision * recall) / (precision + recall)) if precision + recall > 0 else 0.0
        }
        
        os.makedirs('logs', exist_ok=True)
        
        with open('logs/training_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
    
    def plot_training_history(self, save_path: str = "models/training_history.png"):
        """Plot and save training history"""
        if self.history is None:
            print("❌ No training history available")
            return
        
        plt.figure(figsize=(12, 4))
        
        # Accuracy plot
        plt.subplot(1, 2, 1)
        plt.plot(self.history.history['accuracy'], label='Training Accuracy')
        plt.plot(self.history.history['val_accuracy'], label='Validation Accuracy')
        plt.title('Model Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        
        # Loss plot
        plt.subplot(1, 2, 2)
        plt.plot(self.history.history['loss'], label='Training Loss')
        plt.plot(self.history.history['val_loss'], label='Validation Loss')
        plt.title('Model Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        
        plt.tight_layout()
        plt.savefig(save_path)
        plt.close()
        
        print(f"📊 Training history saved to {save_path}")
    
    @staticmethod
    def load_model(model_path: str):
        """
        Load a saved model and tokenizer
        
        Args:
            model_path: Base path of the saved model (without extension)
            
        Returns:
            Tuple of (model, tokenizer, metadata)
        """
        # Load model
        model = tf.keras.models.load_model(f"{model_path}.h5")
        
        # Load tokenizer
        with open(f"{model_path}_tokenizer.pkl", 'rb') as f:
            tokenizer = pickle.load(f)
        
        # Load metadata
        with open(f"{model_path}_metadata.json", 'r') as f:
            metadata = json.load(f)
        
        return model, tokenizer, metadata

def main():
    """Main training function"""
    print("🤖 Deep Learning Model Training Started")
    print("=" * 50)
    
    # Initialize trainer
    trainer = PhishingModelTrainer(max_url_length=200, vocab_size=10000)
    
    # Check if dataset exists
    dataset_path = "data/generated_dataset.csv"
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found at {dataset_path}")
        print("💡 Run dataset_generator.py first to create the dataset")
        return
    
    # Train model
    history = trainer.train_model(dataset_path, epochs=30)
    
    # Save model
    model_path = trainer.save_model()
    
    # Plot training history
    trainer.plot_training_history()
    
    print("\n✅ Model training completed successfully!")
    print(f"📁 Model saved at: {model_path}")

if __name__ == "__main__":
    main()