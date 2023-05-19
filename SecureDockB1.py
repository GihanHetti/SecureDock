####### Secure Dock ########
## Developement by Gihan Hettiarachchi ##

import pefile
import pandas as pd
import numpy as np
import joblib
import os
import math
from colorama import Fore, Style, init

# Initialization for colorama
init(autoreset=True)

# Loadng the trained model
rf_model = joblib.load('rf_model.joblib')

# Loading the StandardScaler object used to scale the training data
scaler = joblib.load('Reprocessed.joblib')

# Extract_features and classify_file functions
def extract_features(file_path):
    try:
        # Getting the file size
        file_length = os.path.getsize(file_path)

        # Calculating the entropy of the file
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
            entropy = 0
            if len(data) > 0:
                # Calculating the frequency of each byte value
                freq_list = []
                for i in range(256):
                    freq_list.append(float(data.count(i)) / len(data))
                # Calculating the entropy of the file
                for freq in freq_list:
                    if freq > 0:
                        entropy += -freq * math.log(freq, 2)

        # Extracting other features from the file
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


# Defineing a function to classify the given file using the trained model
def classify_file(file_path):
    # Extract features from the file
    file_features = extract_features(file_path)
    if file_features is not None:
        # Scale the features using the same StandardScaler object used to scale the training data
        scaled_features = scaler.transform(file_features.values)

        # Making predictions using the trained model
        prediction = rf_model.predict(scaled_features)
        proba = rf_model.predict_proba(scaled_features)

        if prediction[0] == 1 and proba[0][1] >= 0.75:
            print(Fore.RED + f"{file_path} is predicted as a keylogger.")
            print(Fore.RED + "\033[1mDO NOT LAUNCH THIS FILE. IMMEDIATELY DELETE THE FILE!!\033[0m")
            print(f"Probability Rate: {proba[0][1] * 100:.2f}%")
            while True:
                
                delete = input(Fore.RED + """Do you wish to delete this file?\n(It is recomended to delete such files as they have malicious intent) yes/no:""")
                if delete == "yes":
                    try:
                        os.remove(SecureRun.file_path)
                        print("The file has been deleted")
                    except FileNotFoundError:
                        print(f"File '{SecureRun.file_path}' not found.")
                    except PermissionError:
                        print(f"Permission denied: Unable to delete file '{SecureRun.file_path}'.")
                    except Exception as e:
                        print(f"An error occurred while deleting the file: {str(e)}")
                    return
                    
                elif delete == "no":
                    break
                else:
                    print("please enter either yes/no")
                
                
                
        else:
            print(Fore.GREEN + f"{file_path} is predicted as benign.")
            print(f"Probability Rate: {proba[0][1] * 100:.2f}%")
            print(Fore.GREEN + "This File has been deemed safe to open!.")
            
    else:
        print(f"Could not extract features for file: {file_path}")

def print_program_info():
    print(Fore.BLUE + "Welcome to Secure Dock!")
    print(Fore.YELLOW + "This is a program developed by Gihan Hettiarachchi which uses Machine Learning to classify files as benign or keyloggers.")
    print(Fore.YELLOW + "It is recommended to use this application to scan files before launching, as this system was created as a prevention system.\n")
    print(Fore.YELLOW + "Instructions: You will be prompted to enter the path of the file you want to classify.\nSimply enter the path and press Enter.\nThe program will then analyze the file and provide a prediction.\n")
    print(Style.RESET_ALL)

def get_file_path_from_user():
    print(Fore.GREEN + "Please enter the path of the file you wish to scan \nPlease note that the path must be stated as./(or 'q' to quit):")
    file_path = input()
    return file_path

class SecureDock :
    def __init__(self):
        self.filepath = None

    def run_program(self):
        print_program_info()
        while True:
            self.file_path = get_file_path_from_user()
            if self.file_path.lower() == 'q':
                break
            classify_file(self.file_path)

SecureRun = SecureDock()

SecureRun.run_program()



