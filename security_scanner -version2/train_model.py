import pandas as pd
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

# 1. Load the data
print("Loading data...")
if not os.path.exists('data/security_dataset.csv'):
    print("❌ Error: Dataset not found! Run: python dataset_gen.py")
    sys.exit(1)

df = pd.read_csv('data/security_dataset.csv')
X = df['code_snippet']  # The code text
y = df['target']        # The labels (1 = Dangerous, 0 = Safe)

print(f"📊 Loaded {len(df)} samples ({sum(y==1)} dangerous, {sum(y==0)} safe)")

# 2. Split data: 80% for training, 20% for testing 
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 3. Create a Pipeline
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(
        ngram_range=(1, 2),  # Use unigrams and bigrams
        token_pattern=r"(?u)\b\w+\b|[=();]",  # Keep symbols
        min_df=1,
        max_df=0.95
    )),
    ('classifier', LogisticRegression(
        class_weight='balanced',  # Handle imbalanced classes
        max_iter=1000,
        random_state=42
    ))
])

# 4. Train the model
print("Training model...")
pipeline.fit(X_train, y_train)

# 5. Test and Evaluate
print("\n--- Evaluation Results ---")
y_pred = pipeline.predict(X_test)
print(f"🎯 Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=['Safe', 'Dangerous']))

# 6. Save the model for later use
model_filename = 'security_model.joblib'
joblib.dump(pipeline, model_filename)
print(f"\n✅ Model saved to {model_filename}")

# 7. Show example predictions
print("\n--- Example Predictions ---")
test_examples = [
    "os.system('rm -rf ' + user_input)",  # Should be dangerous
    "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",  # Should be safe
    "api_key = 'AKIAIOSFODNN7EXAMPLE'",  # Should be dangerous
    "print('Hello World')"  # Should be safe
]

for example in test_examples:
    prob = pipeline.predict_proba([example])[0]
    prediction = "🚨 DANGEROUS" if prob[1] > 0.5 else "✅ SAFE"
    print(f"{prediction} ({prob[1]:.1%}): {example[:50]}...")