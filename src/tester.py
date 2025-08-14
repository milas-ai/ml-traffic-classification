from csv_preprocessor import preprocess
from pickle import load
import sys

def main():
    if len(sys.argv) != 3:
        print("Usage: python tester.py <model_file> <data_path>")
        exit(1)

    with open(sys.argv[1], 'rb') as model_file:
        model = load(model_file)

    X, y = preprocess(sys.argv[2])

    prediction = model.predict(X)
    print("Predictions:", prediction)

    accuracy = (prediction == y).mean()
    print(f"Accuracy: {accuracy:.2f}")

if __name__ == "__main__":
    main()