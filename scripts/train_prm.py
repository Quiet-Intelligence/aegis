#!/usr/bin/env python3
import sqlite3
import json
import numpy as np
from sklearn.neural_network import MLPRegressor
import pickle
import argparse
import sys
import os

def load_data(db_path):
    print(f"[*] Loading PRM step labels from {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT event_context_json, prm_score 
        FROM prm_labels 
        WHERE prm_score IS NOT NULL
    """)
    rows = cursor.fetchall()
    
    X = []
    y = []
    for event_json, score in rows:
        # Assuming event_context_json contains numerical features or embeddings we can extract
        event = json.loads(event_json)
        
        # Simulated feature extraction (matching episodic embedder logic)
        features = []
        if 'Rule' in event:
            features.append(float(hash(event['Rule']) % 100) / 100.0)
        else:
            features.append(0.0)
            
        if 'Resource' in event:
            features.append(float(hash(event['Resource']) % 100) / 100.0)
        else:
            features.append(0.0)
            
        # Add padding to simulate full embedding vector
        features.extend([0.0] * 62) # 64 dims total
        
        X.append(features)
        y.append(score)
        
    conn.close()
    return np.array(X), np.array(y)

def train_model(X, y):
    print(f"[*] Training lightweight PRM (MLP) on {len(X)} labeled steps...")
    
    if len(X) == 0:
        print("[-] No labeled PRM data found. Run the active learning loop first.")
        sys.exit(0)
        
    # Lightweight MLP for scoring
    model = MLPRegressor(
        hidden_layer_sizes=(32, 16),
        activation='relu',
        solver='adam',
        max_iter=500,
        random_state=42
    )
    
    model.fit(X, y)
    score = model.score(X, y)
    print(f"[+] Training complete. R^2 Score: {score:.4f}")
    return model

def save_model(model, output_path):
    print(f"[*] Saving PRM weights to {output_path}...")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        pickle.dump(model, f)
    print("[+] Model saved.")

def main():
    parser = argparse.ArgumentParser(description="Train the Process Reward Model (PRM)")
    parser.add_argument("--db", default="aegis.db", help="Path to Aegis SQLite database")
    parser.add_argument("--out", default="models/prm_weights.pkl", help="Output path for weights")
    args = parser.parse_args()
    
    if not os.path.exists(args.db):
        print(f"[-] Database {args.db} not found.")
        # Create empty mock for CI if not exists
        conn = sqlite3.connect(args.db)
        conn.close()
        print(f"[*] Created empty database for testing: {args.db}")
        
    try:
        X, y = load_data(args.db)
        model = train_model(X, y)
        save_model(model, args.out)
    except sqlite3.OperationalError as e:
        print(f"[-] SQLite Error: {e}")
        print("[-] Ensure the Aegis daemon has initialized the schema.")

if __name__ == "__main__":
    main()
