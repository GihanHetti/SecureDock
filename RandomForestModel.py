####### Secure Dock ########
## Developement by Gihan Hettiarachchi ##


import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load dataset - Used preprocessed dataset that created using data_preprocessing_pe_files.py
dataset = pd.read_csv('Preprocessed_key_dataset.csv')

# Create dependent & independent variable vectors
x = dataset.iloc[:, :-1].values  #(removed only classification_list )
y = dataset.iloc[:,-1].values #dependent - classification_list (Blacklist = 1 / Whitelist = 0)


# Split the dataset for training & testing
from sklearn.model_selection import train_test_split
x_train, x_test, y_train, y_test = train_test_split(x,y,test_size=0.20,random_state=42)

print("Train Shpae:",x_train.shape, "\nTest Shape:", x_test.shape)


## Random Forest
from sklearn.ensemble import RandomForestClassifier

rfc = RandomForestClassifier(max_depth=32, random_state=0)
randomModel = rfc.fit(x_train, y_train)


### Model Evaluation
from sklearn.metrics import f1_score,accuracy_score,confusion_matrix,r2_score,precision_score

### Accuracy on the train dataset
rf_y_train_pred = randomModel.predict(x_train)
trainAS = round(accuracy_score(y_train, rf_y_train_pred)*100, 4)

### Accuracy on the test dataset - validation accuracy
rf_y_test_pred = randomModel.predict(x_test)
testAS = accuracy_score(y_test, rf_y_test_pred)
val_loss = round((1 - testAS)*100, 4)
val_accurcy = round(testAS*100, 4)

# Calculate precision
precision = round(precision_score(y_test, rf_y_test_pred)*100, 4)

# Calculate F1 Score
f1 = round(f1_score(y_test, rf_y_test_pred)*100, 4)

# Calculate R2 score
r2 = round(r2_score(y_test, rf_y_test_pred)*100, 4)


print("\nAccuracy on the train dataset:", trainAS)
print("Validation Accuracy:", val_accurcy)
print("Validation Loss:", val_loss)
print("Precision:", precision)
print("F1 Score:", f1)
print("R2 Score:", r2)


## Confusion matrix - Random Forest
### Confusion matrix without Normalization
conf_matrix = confusion_matrix(y_test, rf_y_test_pred)

### Confusion matrix with Normalization
conf_matrix_norm = confusion_matrix(y_test, rf_y_test_pred, normalize='true')

# Calculate TP, TN, FP, FN
TP = round(conf_matrix_norm[1, 1]*100, 4)
TN = round(conf_matrix_norm[0, 0]*100, 4)
FP = round(conf_matrix_norm[0, 1]*100, 4)
FN = round(conf_matrix_norm[1, 0]*100, 4)

print("\nTrue Positives (TP):", TP)
print("True Negatives (TN):", TN)
print("False Positives (FP):", FP)
print("False Negatives (FN):", FN)



#Save ML Model
from joblib import dump

dump(randomModel, 'rf_model.joblib')
# ---------- ##