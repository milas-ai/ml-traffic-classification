import pandas as pd
import ipaddress
import os

def preprocess(data_file):
    if os.path.isdir(data_file):
        csv_files = [os.path.join(data_file, file) for file in os.listdir(data_file) if file.endswith('.csv')]
        all_X = []
        all_y = []
        for csv_file in csv_files:
            X, y = preprocess_file(csv_file)
            all_X.append(X)
            all_y.append(y)
        # Concatenate all processed data
        X = pd.concat(all_X, ignore_index=True)
        y = pd.concat(all_y, ignore_index=True)
        return X, y
    else:
        return preprocess_file(data_file)

def preprocess_file(csv_file):
    df = pd.read_csv(csv_file)
    
    # Remove empty columns (unnamed columns created by trailing commas)
    unnamed_cols = [col for col in df.columns if col.startswith('Unnamed:')]
    if unnamed_cols:
        df = df.drop(unnamed_cols, axis=1)
    if '' in df.columns:
        df = df.drop('', axis=1)
    
    # Create a copy for processing
    processed_df = df.copy()
    
    # Handle IP addresses
    if 'saddr' in processed_df.columns:
        processed_df['saddr_int'] = processed_df['saddr'].apply(lambda x: convertIpToInt(x))

    if 'daddr' in processed_df.columns:
        processed_df['daddr_int'] = processed_df['daddr'].apply(lambda x: convertIpToInt(x))
    
    # Handle hex flags
    if 'flgs' in processed_df.columns:
        processed_df['flgs_int'] = processed_df['flgs'].apply(lambda x: convertFlagsToInt(x))
       
    # Transform attack column to label
    if 'attack' in processed_df.columns:
        processed_df['label'] = processed_df['attack'].astype(int)
    else:
        processed_df['label'] = -1  # Default label if 'attack' column is missing

    # Separate features and target
    exclude_columns = ['pkSeqID', 'category', 'subcategory', 'attack', 'stime', 'ltime', 'saddr', 'daddr', 'flgs', 'attack']

    feature_columns = [col for col in processed_df.columns if col not in exclude_columns and col != 'label']
    
    # Ensure all features are numeric
    for col in feature_columns:
        processed_df[col] = pd.to_numeric(processed_df[col], errors='coerce')
    
    processed_df[feature_columns] = processed_df[feature_columns].fillna(0)
    
    # Prepare features (X) and target (y)
    X = processed_df[feature_columns]
    y = processed_df['label']

    return X, y

def convertIpToInt(ip_str):
    try:
        return int(ipaddress.IPv4Address(ip_str))
    except:
        return 0

def convertFlagsToInt(flag_str):
    try:
        if isinstance(flag_str, str) and flag_str.startswith('0x'):
            return int(flag_str, 16)
        return int(flag_str) if flag_str else 0
    except:
        return 0

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python csv_preprocessor.py <data_path> <output_file>")
        exit(1)
    
    X, y = process(sys.argv[1])
    
    X['label'] = y
    X.to_csv(sys.argv[2], index=False)

    print(f"Processed data saved to {sys.argv[2]}")
