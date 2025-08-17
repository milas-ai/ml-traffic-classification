from pickle import load
from csv_preprocessor import preprocess
from pcap_processor import pcapToCSV, getFeaturesFromFile, getDefaultFeatures, pcapSample
from subprocess import Popen, DEVNULL
from threading import Thread
import time
import sys
import os

CAPTURE_TIME = 30
SAMPLE_SIZE = 1000 # Maximum tested sample size is 5000 packets

class PacketCapturer:
    def __init__(self):
        self.capture_process = None

    def startCapture(self):
        self.capture_thread = Thread(target=self.startCaptureProcess)
        self.capture_thread.start()

    def startCaptureProcess(self):
        self.capture_process = Popen(["tshark", "-i", "any", "-f", "tcp", "-w", "capture.pcapng"], stdout=DEVNULL, stderr=DEVNULL)
        log("Capture started")
        self.capture_process.wait()

    def stopCapture(self):
        if self.capture_process:
            self.capture_process.terminate()
            self.capture_process.wait()
            self.capture_process = None
            self.capture_thread.join()
            self.capture_thread = None
            log("Capture stopped")
        
    def timer(self, seconds):
        time.sleep(seconds)
        self.stopCapture()

def log(message):
    log_message = f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}"
    with open("monitor.log", "a") as log_file:
        log_file.write(log_message)
        log_file.write("\n")
    print(log_message)

def main():
    if len(sys.argv) not in [2,3]:
        print("Usage: python monitor.py <model_file> [features_file]")
        exit(1)

    with open(sys.argv[1], 'rb') as model_file:
        model = load(model_file)

    if len(sys.argv) == 3:
        packet_features = getFeaturesFromFile(sys.argv[2])
    else:
        packet_features = getDefaultFeatures()

    try:
        while True:
            # Capture packets for CAPTURE_TIME seconds
            capturer = PacketCapturer()
            capturer.startCapture()
            capturer.timer(CAPTURE_TIME)

            # Convert the captured packets to CSV to be used for training
            packet_count = pcapSample("capture.pcapng", SAMPLE_SIZE)
            log(f"Total packets captured: {packet_count}")
            pcapToCSV("capture.pcapng", "capture.csv", packet_features)
            X, y = preprocess("capture.csv")

            # Traffic classification
            y_pred = model.predict(X)
            log(f"{y_pred.sum()/len(y_pred) * 100:.2f}% of the packets are classified as malicious")

            # Clean up
            if os.path.exists("capture.pcapng"):
                os.remove("capture.pcapng")
            if os.path.exists("capture.csv"):
                os.remove("capture.csv")

    except KeyboardInterrupt:
        print("", end="\r")
        capturer.stopCapture()
        log("Monitoring stopped by user")
        if os.path.exists("capture.pcapng"):
            os.remove("capture.pcapng")
        if os.path.exists("capture.csv"):
            os.remove("capture.csv")
        if os.path.exists("sampled_pcap.pcapng"):
            os.remove("sampled_pcap.pcapng")
        exit(0)

if __name__ == "__main__":
    main()
