import os
import csv
import shutil
from datetime import datetime

import config
from PacketReader import PacketReader
from BasicFlow import BasicFlow
import FlowFeature
from SampleData import sampleData
from utils import OutputInfo


def getLabel(dirName):
    last_char = dirName[-1]
    penultimate_char = dirName[-2]
    if penultimate_char.isdigit():
        return None
    if last_char.isdigit():
        if int(last_char) != 0 and dirName[:-1] != "Benign":
            return None
        return dirName[:-1]
    return dirName


def process(pcapFile):
    # 初始化PCAP数据包读取类
    packetReader = PacketReader(pcapFile)
    # 读取第一个数据包
    packet = packetReader.nextPacket()
    # 初始化会话流
    flow = BasicFlow(
        packet=packet,
        activityTimeout=config.activityTimeout,
        subFlowTimeout=config.subFlowTimeout,
        packetNumMax=config.packetNumMax,
        packetLenMax=config.packetLenMax,
    )
    # 循环读取数据包,直到结束
    while packet is not None:
        # 将其添加到会话流中
        flow.addPacket(packet=packet)
        # 读取下一个数据包
        packet = packetReader.nextPacket()
    # 结束流
    flow.endSession()
    return flow


def extractData(args):
    # 如果文件夹存在则删除
    if os.path.exists(args.extractDataPath) == True:
        print("Deleting Old Datas...")
        shutil.rmtree(args.extractDataPath)
    # 创建数据提取文件夹
    os.mkdir(args.extractDataPath)

    # 创建统计特征文件夹(包括统计特征和包长分布)
    stcDataPath = args.extractDataPath + "statistics/"
    os.mkdir(stcDataPath)
    # 创建负载信息文件夹
    pldDataPath = args.extractDataPath + "payload/"
    os.mkdir(pldDataPath)

    print(datetime.now())

    featureName = FlowFeature.getFeatureName()
    outputInfo = OutputInfo(args.extractDataPath, featureName)

    # 获取文件夹下的所有文件夹名称
    dirs = os.listdir(args.pcapPath)
    for dir in dirs:
        label = getLabel(dir)
        if label == None:
            continue

        print("process", dir)

        outputInfo.check(label)

        # 获取文件夹名称
        dirpath = os.path.join(args.pcapPath, dir)
        # 获取文件夹下的所有文件夹名称
        files = os.listdir(dirpath)
        # 遍历所有文件
        for f in files:
            # 获取文件路径
            pcapFile = os.path.join(dirpath, f)
            # 处理PCAP文件
            flow = process(pcapFile)

            # 生成统计特征和包长分布
            features = flow.generateFlowFeatures()

            # 如果特征为空(只有当第一个数据包的时间戳等于最后一个数据包的时间戳的时候才会出现该情况)
            if features is None:
                # print(f)  # 打印文件名, 调试用
                continue  # 略过该文件

            # 添加标签
            features.append(label)

            statisticsFile, payloadFile = outputInfo.getFile(label)
            # 写入到文件
            with open(statisticsFile, "a", newline="") as csvFile:
                # 创建writer对象
                writer = csv.writer(csvFile)
                writer.writerow(features)

            # 生成负载数据
            payloads = flow.getPayloads()
            # 写入到文件
            with open(payloadFile, "a", newline="") as csvFile:
                # 创建writer对象
                writer = csv.writer(csvFile)
                for pld in payloads:
                    writer.writerow(pld)

        # 打印时间
        print(datetime.now())


if __name__ == "__main__":
    args = config.parser.parse_args()

    # 提取特征
    print("Extracting Features...")
    extractData(args)

    # 采样数据
    print("Sampling Datas...")
    sampleData(args)
