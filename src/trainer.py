import pandas as pd
import numpy as np
import sys
from sklearn.tree import DecisionTreeClassifier
from csv_preprocessor import preprocess
from pickle import dump

def main():
    if len(sys.argv) != 3:
        print("Usage: python trainer.py <data_path> <model_output_file>")
        exit(1)

    X,y = preprocess(sys.argv[1])
    
    model = DecisionTreeClassifier()
            #    random_state=42,
            #max_depth=10,  # Prevent overfitting
            #min_samples_split=5,
            #min_samples_leaf=2
            #)

    model.fit(X, y)

    with open(sys.argv[2], 'wb') as output_file:
        dump(model, output_file)

    print("Model trained and saved as {}".format(sys.argv[2]))

if __name__ == "__main__":
    main()