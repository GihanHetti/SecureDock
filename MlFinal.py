# Secure Dock #
# Developement by Gihan Hettiarachchi #
# ML Model #

import pefile
import pandas as pd
import numpy as np
import joblib
import os
import math

# Load the trained model
rf_model = joblib.load('rf_model.joblib')

# Load the StandardScaler object used to scale the training data
scaler = joblib.load('Reprocessed.joblib')

# Define a function to extract the required features from the given file
def extract_features(file_path):
    try:
	    # Get the file size
        file_length = os.path.getsize(file_path)
        
        # Calculate the entropy of the file
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
            entropy = 0
            if len(data) > 0:
                # Calculate the frequency of each byte value
                freq_list = []
                for i in range(256):
                    freq_list.append(float(data.count(i))/len(data))
                # Calculate the entropy of the file
                for freq in freq_list:
                    if freq > 0:
                        entropy += -freq * math.log(freq, 2)
        
        # Extract other features from the file
        pe = pefile.PE(file_path)
        features = {
            'machine_type': pe.FILE_HEADER.Machine,
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'pointer_to_symbol_table': pe.FILE_HEADER.PointerToSymbolTable,
            'number_of_symbols': pe.FILE_HEADER.NumberOfSymbols,
            'size_of_optional_header': pe.FILE_HEADER.SizeOfOptionalHeader,
            'characteristics': pe.FILE_HEADER.Characteristics,
            'iat_rva': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].VirtualAddress,
            'major_version': pe.OPTIONAL_HEADER.MajorLinkerVersion,
            'minor_version': pe.OPTIONAL_HEADER.MinorLinkerVersion,
            'check_sum': pe.OPTIONAL_HEADER.CheckSum,
            'compile_date': pe.FILE_HEADER.TimeDateStamp,
            'datadir_IMAGE_DIRECTORY_ENTRY_BASERELOC_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].Size,
            'datadir_IMAGE_DIRECTORY_ENTRY_EXPORT_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size,
            'datadir_IMAGE_DIRECTORY_ENTRY_IAT_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].Size,
            'datadir_IMAGE_DIRECTORY_ENTRY_IMPORT_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].Size,
            'debug_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']].Size,
            'export_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']].Size,
            'size_of_code': pe.OPTIONAL_HEADER.SizeOfCode,
            'size_of_initialized_data': pe.OPTIONAL_HEADER.SizeOfInitializedData,
            'size_of_uninitialized_data': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
            'size_of_image': pe.OPTIONAL_HEADER.SizeOfImage,
            'size_of_headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'major_operating_system_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            'minor_operating_system_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            'number_of_rva_and_sizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
            'base_of_code': pe.OPTIONAL_HEADER.BaseOfCode,
            'entry_point_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'resource_size': pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']].Size,
            'size_of_heap_commit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
            'size_of_heap_reserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
            'size_of_stack_commit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
            'size_of_stack_reserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
            'status': pe.OPTIONAL_HEADER.DllCharacteristics,
            'file_length': file_length,
            'entropy': entropy,
        }
        return pd.DataFrame(features, index=[0])
    except Exception as e:
        print(f"Error while processing file: {file_path}")
        print(f"Error message: {str(e)}")
        return None


# Define a function to classify the given file using the trained model
def classify_file(file_path):
    # Extract features from the file
    file_features = extract_features(file_path)
    if file_features is not None:
        # Scale the features using the same StandardScaler object used to scale the training data
        scaled_features = scaler.transform(file_features.values)
        
        # Make predictions using the trained model
        prediction = rf_model.predict(scaled_features)
        proba = rf_model.predict_proba(scaled_features)
        print(f"Prediction: {prediction} ")
        print(f"Prediction Probability: {proba[0][1]:.2f}")
        
        if prediction[0] == 1 and proba[0][1] >= 0.75:
            print(f"{file_path} is predicted as keylogger.")
            print(f"Probability Rate: {proba[0][1]*100:.2f}%")
        else:
            print(f"{file_path} is predicted as benign.")
            print(f"Probability Rate: {proba[0][1]*100:.2f}%")
    else:
        print(f"Could not extract features for file: {file_path}")

# Call the classify_file function with the file path of the file you want to classify
#file_path = './SafeFile/VisualStudioSetup.exe'
#file_path = './SafeFile/DiscordSetup.exe'
#file_path = './DangerKeyloggers/61242d372c2335940696dbf6d7ea85fbd95bd192d40a2e347faf43d9cbd04c82/61242d372c2335940696dbf6d7ea85fbd95bd192d40a2e347faf43d9cbd04c82'
#file_path = './DangerKeyloggers/pastanovemberpennsylvaniacarolina_1/pastanovemberpennsylvaniacarolina'
#file_path = './DangerKeyloggers/ZebraBlackVictorOrange/fatura_25148'

# Prompt the user to enter a file path
file_path = input("Please enter the path of the file to classify: ")

classify_file(file_path)

