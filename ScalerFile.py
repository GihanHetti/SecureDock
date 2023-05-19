## Secure Dock ##
## Development by Gihan Hettiarachchi ##
## Feature Scaling - Standardization ##

from sklearn.preprocessing import StandardScaler
import joblib
import pandas as pd

# Load dataset
dataset = pd.read_csv('Keylogger_Exe_dataset_copy.csv')

# Create dependent & independent variable vectors
x = dataset.iloc[:, :-1].values #independent - pe file features
y = dataset.iloc[:,-1].values #dependent - classification_list (Blacklist = 1 / Whitelist = 0)

# Initialize the scaler
scaler = StandardScaler()

# Fit the scaler to the data
scaler.fit(x)

# Save the scaler as a joblib file
joblib.dump(scaler, 'Reprocessed.joblib')