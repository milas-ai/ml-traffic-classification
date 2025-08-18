from subprocess import Popen, PIPE, DEVNULL
from random import sample
import pyshark
import time
import sys
import os

RECORD_TIMEOUT = 5
DEFAULT_FEATURES = {
    "pkSeqID": 1,
    "stime": -1,
    "flgs": -1,
    "proto": -1,
    "saddr": -1,
    "sport": -1,
    "daddr": -1,
    "dport": -1,
    "pkts": -1,
    "bytes": -1,
    "ltime": -1,
    "seq": -1,
    "dur": -1,
    "mean": -1,
    "stddev": -1,
    "sum": 0,
    "min": -1,
    "max": -1,
    "spkts": -1,
    "dpkts": -1,
    "sbytes": -1,
    "dbytes": -1,
    "rate": -1,
    "srate": -1,
    "drate": -1
}

class PcapProcessor:
    newRecord = False
    output_file = None
    packet_features = {}
    durations = []
    
    def __init__(self, capture_file, output_file, packet_features, classification):
        self.capture = pyshark.FileCapture(capture_file, keep_packets=False)
        self.packet_features = packet_features

        if classification != None:
            self.packet_features["attack"] = {
                "value": classification["attack"],
                "name": "attack",
                "locked": True
            }
            self.packet_features["category"] = {
                "value": classification["category"],
                "name": "category",
                "locked": True
            }
            self.packet_features["sub_category"] = {
                "value": classification["subcategory"],
                "name": "subcategory",
                "locked": True
            }

        self.output_file = open(output_file, "w")

    def createOutput(self):
        # Write the header to the output file
        for feature in self.packet_features.values():
            self.output_file.write(f"{feature['name']},")
        self.output_file.write("\n")

        for packet in self.capture:
            if packet.IP.src != self.packet_features["saddr"]["value"] or packet.IP.dst != self.packet_features["daddr"]["value"] or packet.IP.proto != self.packet_features["proto"]["value"]:
                if packet.IP.src != self.packet_features["daddr"]["value"] and packet.IP.dst != self.packet_features["saddr"]["value"]:
                    self.newRecord = True
                else:
                    self.updateRecord(packet) # Awnswer transaction
            else:
                self.updateRecord(packet) # Existing transaction

            if self.newRecord:
                if self.packet_features["stime"]["value"] != -1:
                    self.wrapUpRecord()
                    self.writeRecord()
                self.createRecord(packet)
        self.wrapUpRecord()
        self.writeRecord()
        self.capture.close()
        self.output_file.close()

    def writeRecord(self):
        for key, feature in self.packet_features.items():
            if feature["name"] != "":
                self.output_file.write(f"{feature['value']},")
        self.output_file.write("\n")
        self.packet_features["pkSeqID"]["value"] += 1

    def createRecord(self, packet):
        self.packet_features["stime"]["value"] = (float)(packet.sniff_timestamp)
        self.packet_features["flgs"]["value"] = packet.IP.flags
        self.packet_features["proto"]["value"] = packet.IP.proto
        self.packet_features["saddr"]["value"] = packet.IP.src
        self.packet_features["daddr"]["value"] = packet.IP.dst
        if "TCP" in packet:
            self.packet_features["sport"]["value"] = packet.TCP.srcport
            self.packet_features["dport"]["value"] = packet.TCP.dstport
        elif "UDP" in packet:
            self.packet_features["sport"]["value"] = packet.UDP.srcport
            self.packet_features["dport"]["value"] = packet.UDP.dstport
        else:
            self.packet_features["sport"]["value"] = ""
            self.packet_features["dport"]["value"] = ""
        self.packet_features["pkts"]["value"] = 1
        self.packet_features["bytes"]["value"] = (int)(packet.length)
        # state
        self.packet_features["ltime"]["value"] = (float)(packet.sniff_timestamp)
        # seq
        self.packet_features["spkts"]["value"] = 1
        self.packet_features["dpkts"]["value"] = 0
        self.packet_features["sbytes"]["value"] = (int)(packet.length)
        self.packet_features["dbytes"]["value"] = 0

    def updateRecord(self, packet):
        self.packet_features["pkts"]["value"] += 1
        self.packet_features["flgs"]["value"] = packet.IP.flags
        self.packet_features["proto"]["value"] = packet.IP.proto
        self.packet_features["bytes"]["value"] += (int)(packet.length)
        if packet.IP.src == self.packet_features["saddr"]["value"]:
            self.packet_features["spkts"]["value"] += 1
            self.packet_features["sbytes"]["value"] += (int)(packet.length)
        else:
            self.packet_features["dpkts"]["value"] += 1
            self.packet_features["dbytes"]["value"] += (int)(packet.length)
        self.packet_features["ltime"]["value"] = (float)(packet.sniff_timestamp)
        if self.packet_features["ltime"]["value"] - self.packet_features["stime"]["value"] > RECORD_TIMEOUT:
            self.newRecord = True

    def wrapUpRecord(self):
        self.packet_features["dur"]["value"] = self.packet_features["ltime"]["value"] - self.packet_features["stime"]["value"]
        self.packet_features["sum"]["value"] += self.packet_features["dur"]["value"]
        self.durations.append(self.packet_features["dur"]["value"])
        self.packet_features["min"]["value"] = self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] < self.packet_features["min"]["value"] or self.packet_features["min"]["value"] == -1 else self.packet_features["min"]["value"]
        self.packet_features["max"]["value"] = self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] > self.packet_features["max"]["value"] or self.packet_features["max"]["value"] == -1 else self.packet_features["max"]["value"]
        self.packet_features["mean"]["value"] = self.packet_features["sum"]["value"] / self.packet_features["pkts"]["value"]

        stddevSum = 0
        for duration in self.durations:
            stddevSum += (duration - self.packet_features["mean"]["value"]) ** 2
        self.packet_features["stddev"]["value"] = (stddevSum / self.packet_features["pkts"]["value"]) ** 0.5

        self.packet_features["rate"]["value"] = self.packet_features["pkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0
        self.packet_features["srate"]["value"] = self.packet_features["spkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0
        self.packet_features["drate"]["value"] = self.packet_features["dpkts"]["value"] / self.packet_features["dur"]["value"] if self.packet_features["dur"]["value"] != 0 else 0

def getFeaturesFromFile(feature_file_path):
    packet_features = {}
    with open(feature_file_path, "r") as feature_file:
        for line in feature_file.readlines()[1:]:
            key, value, name, locked = line.strip().split(",")
            if key in ["stime","ltime","dur","mean","stddev","sum","min","max","rate","srate","drate"]:
                value = float(value)
            else:
                try:
                    value = int(value)
                except:
                    pass

            packet_features[key] = {
                "value": value,
                "default_value": value,
                "name": name,
                "locked": locked == "True"
            }

        for key, value in DEFAULT_FEATURES.items():
            if key not in self.packet_features:
                self.packet_features[key] = {
                    "value": value,
                    "default_value": value,
                    "name": "",
                    "locked": False
                }

def getDefaultFeatures(): 
    packet_features = {}
    for feature, value in DEFAULT_FEATURES.items():
        if feature in ["stime","ltime","dur","mean","stddev","sum","min","max","rate","srate","drate"]:
            value = float(value)
        else:
            try:
                value = int(value)
            except:
                pass
        packet_features[feature] = {
            "name": feature,
            "value": value,
        }
    return packet_features

def pcapSample(pcap_file, sample_size=1000):
    # Get the number of packets in the capture file and sample a subset if necessary
    aux_process = Popen(["capinfos", "-Trc", pcap_file], stdout=PIPE, stderr=DEVNULL)
    aux_process.wait()
    packet_count, _ = aux_process.communicate()
    try:
        packet_count = int(packet_count.decode().strip().split("\t")[-1].split(" ")[-1])
    except:
        packet_count = 0

    if packet_count > sample_size:
        packet_numbers = sample(range(1, packet_count + 1), sample_size)
        packet_numbers.sort()
        filter_expression = " || ".join([f"frame.number == {num}" for num in packet_numbers])
        # Use tshark with the filter to create a new pcap file with sampled packets
        aux_process = Popen(["tshark", "-r", pcap_file, "-Y", filter_expression, "-w", "sampled_pcap.pcapng"], stderr=DEVNULL)
        aux_process.wait()
        os.remove(pcap_file)
        os.rename("sampled_pcap.pcapng", pcap_file)

    return packet_count

def pcapToCSV(pcap_file, output_file, packet_features, classification=None):
    data_collector = PcapProcessor(pcap_file, output_file, packet_features, classification)
    data_collector.createOutput()

def main():
    if len(sys.argv) not in [3, 4, 6, 7]:
        print("Usage: python pcap_processor.py <pcap_file> <output_file> [features_file] [attack category subcategory]")
        exit(1)

    pcap_file = sys.argv[1]
    output_file = sys.argv[2]

    if len(sys.argv) in [4, 7]:
        packet_features = getFeaturesFromFile(sys.argv[3])
    else:
        packet_features = getDefaultFeatures()

    if len(sys.argv) in [6, 7]:
        classification = {
            "attack": int(sys.argv[-3]),
            "category": sys.argv[-2],
            "subcategory": sys.argv[-1]
        }
        pcapToCSV(pcap_file, output_file, packet_features, classification)
    else:
        pcapToCSV(pcap_file, output_file, packet_features)

    print(f"Processed {pcap_file} and saved to {output_file}")
    
if __name__ == "__main__":
    main()
