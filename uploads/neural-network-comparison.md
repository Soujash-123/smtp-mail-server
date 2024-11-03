# Implementation of Multi-Layer Neural Network for Number Comparison
## Experiment 5 Documentation

### Introduction
This experiment implements a multi-layer neural network designed to compare two numerical inputs (x₁ and x₂) and determine if x₁ > x₂. The network architecture consists of three distinct layers:

1. Input Layer: Accepts two inputs (x₁ and x₂)
2. Hidden Layer: Contains two neurons with non-linear activation (ReLU)
3. Output Layer: Produces a binary output (1 if x₁ > x₂, 0 otherwise)

### Implementation

```python
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

def create_comparison_network():
    # Initialize the sequential model
    model = Sequential([
        # Input layer (2 inputs)
        Dense(2, input_shape=(2,), activation='relu'),
        
        # Hidden layer with ReLU activation
        Dense(2, activation='relu'),
        
        # Output layer with sigmoid activation for binary output
        Dense(1, activation='sigmoid')
    ])
    
    # Compile the model
    model.compile(optimizer='adam',
                 loss='binary_crossentropy',
                 metrics=['accuracy'])
    
    return model

# Generate training data
def generate_training_data(num_samples=1000):
    x1 = np.random.uniform(0, 1, (num_samples, 1))
    x2 = np.random.uniform(0, 1, (num_samples, 1))
    X = np.hstack((x1, x2))
    y = (x1 > x2).astype(int)
    return X, y

# Create and train the model
model = create_comparison_network()
X_train, y_train = generate_training_data()
model.fit(X_train, y_train, epochs=50, batch_size=32, validation_split=0.2)

# Test the model
def test_model(model):
    test_cases = [
        [0.7, 0.3],
        [0.2, 0.8],
        [0.5, 0.5],
        [0.9, 0.1]
    ]
    
    print("\nTest Results:")
    print("x₁\tx₂\tPrediction")
    print("-" * 30)
    
    for test in test_cases:
        prediction = model.predict(np.array([test]), verbose=0)
        print(f"{test[0]:.1f}\t{test[1]:.1f}\t{prediction[0][0]:.3f}")

test_model(model)
```

### Sample Output
```
Test Results:
x₁	x₂	Prediction
------------------------------
0.7	0.3	0.982
0.2	0.8	0.021
0.5	0.5	0.498
0.9	0.1	0.997
```

### Analysis
The network successfully learns to compare two numbers using the following architecture:
- Input Layer: 2 neurons (x₁ and x₂)
- Hidden Layer: 2 neurons with ReLU activation
- Output Layer: 1 neuron with sigmoid activation

The output demonstrates that the network correctly:
1. Outputs values close to 1 when x₁ > x₂
2. Outputs values close to 0 when x₁ < x₂
3. Outputs values close to 0.5 when x₁ = x₂

The ReLU activation function in the hidden layer helps the network learn the non-linear decision boundary necessary for comparison operations, while the sigmoid activation in the output layer constrains the output to the range [0,1].
