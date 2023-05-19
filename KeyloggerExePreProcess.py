#### Data Pre-processing PE Files ####

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Load dataset
dataset = pd.read_csv('Keylogger_Exe_dataset.csv')
dataset.shape
dataset.describe()

# Create dependent & independent variable vectors
x = dataset.iloc[:,1:-1].values #independent - other features (removed file_name & classification_list)
y = dataset.iloc[:,-1].values #dependent - classification_list

# Handle missing data
# Count the num of missing values in each column - output = 0
# print(dataset.isnull().sum()) 

# Data Encoding
## Label Encoding
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()

y = le.fit_transform(y)
y = np.where(y == 0, 1, 0) # Blacklist = 1 / Whitelist = 0

# Feature Scaling - Standardization
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
x = scaler.fit_transform(x)


# Create a new DataFrame with preprocessed data
preprocessed_df = pd.DataFrame(data=x, columns=dataset.columns[1:-1])

# Add the classification column to the preprocessed DataFrame
preprocessed_df['classification_list'] = y

# Save preprocessed dataset as CSV file
preprocessed_df.to_csv('Preprocessed_key_dataset.csv', index=False)
print("Dataset Creation Successfully Completed!!!")