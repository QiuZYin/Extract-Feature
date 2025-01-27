import argparse

dataset = "CICIDS2017"

parser = argparse.ArgumentParser(description="Extract Feature")

parser.add_argument(
    "--pcapPath",
    default="../Datas/" + dataset + "/raw data",
    help="path to pcap file or pcap dir",
)
parser.add_argument(
    "--extractDataPath",
    default="../Datas/" + dataset + "/extract data/",
    help="path to extract data dir",
)
parser.add_argument(
    "--sampleDataPath",
    default="../Datas/" + dataset + "/sample data/",
    help="path to sample data dir",
)
parser.add_argument(
    "--flag",
    default=0b11,
    help="sample information",
    # 分别表示 statistics, payload 是否要采样
)

activityTimeout = 5000000
subFlowTimeout = 1000000
packetNumMax = 16
packetLenMax = 128

PathError = "Error Code = 00, There is no Such File or Folder."
AttackInfoLack = "Error Code = 01, The Attack Information File is Missing."
PcapHeaderError = "Error Code = 02, This is not a Pcap File."
