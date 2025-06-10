# Network Traffic Analysis System

This project implements a real-time network traffic analysis system using machine learning to predict and classify network flows. The system captures network packets, extracts flow features, and uses a Random Forest model to predict the type of network traffic.

## Project Structure

```
├── src/                    # Source code
│   ├── network_analyzer.py # Main application code
│   └── utils.py           # Utility functions
├── models/                 # Trained models
│   ├── random_forest.pkl  # Random Forest model
│   ├── scaler.pkl         # Feature scaler
│   └── label_encoder.pkl  # Label encoder
├── data/                   # Data files
│   ├── flow_features.csv  # Flow features dataset
│   └── predictions.csv    # Prediction results
├── notebooks/             # Jupyter notebooks
│   ├── random_forest.ipynb
│   ├── random_forest_xg_boost_without_smote.ipynb
│   └── xg_boost.ipynb
└── docs/                  # Documentation
    └── presentation.pdf   # Project presentation
```

## Features

- Real-time network packet capture
- Flow feature extraction
- Machine learning-based traffic classification
- Alert system for suspicious traffic
- Interactive web interface using Streamlit

## Requirements

- Python 3.7+
- Required packages:
  - streamlit
  - scapy
  - pandas
  - numpy
  - scikit-learn
  - joblib
  - jupyter
  - xgboost

## Installation

1. Clone the repository
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the application:
```bash
streamlit run src/network_analyzer.py
```

## Development

The project includes Jupyter notebooks in the `notebooks/` directory for model development and experimentation:
- `random_forest.ipynb`: Random Forest model development
- `random_forest_xg_boost_without_smote.ipynb`: XGBoost model development without SMOTE
- `xg_boost.ipynb`: XGBoost model development

## License

MIT License 