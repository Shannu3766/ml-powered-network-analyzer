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

## Interface Preview

### Warning Alert Interface
![Warning Alert Interface](docs\images\warning_alert.jpg)
*The warning alert interface shows real-time detection of suspicious network traffic with detailed information about the detected threats.*

## Model Generation

The trained models in the `models/` directory are generated when you run the Jupyter notebooks in the `notebooks/` directory:

1. `random_forest.ipynb`: Generates `models/random_forest.pkl`
2. `random_forest_xg_boost_without_smote.ipynb`: Generates XGBoost model
3. `xg_boost.ipynb`: Generates additional XGBoost model

To generate the models:
1. Navigate to the `notebooks/` directory
2. Run the notebooks in order:
   ```bash
   jupyter notebook
   ```
3. Execute all cells in each notebook
4. The models will be automatically saved to the `models/` directory

Note: Make sure to run the notebooks before using the main application, as the application requires these trained models to function.

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
3. Generate the models by running the notebooks (see Model Generation section)

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