import os
import csv
import random
import shutil
import numpy as np
import pandas as pd

import config

MAX_SESS_LEN = config.packetNumMax


def writePLD(oldfile: str, newfile: str, newpath: str, sampleNum: int, indexList: list):
    """
    写入负载信息和负载附加信息

    Parameters
    ----------
    oldfile : str
        原文件(被采样的文件)

    newfile : str
        新文件(保存采样结果的文件)

    newpath : str
        新路径(保存采样结果的文件夹)

    sampleNum : int
        采样数量

    indexList : list
        索引列表

    Returns
    -------
    None

    """
    # 读取原文件
    oldfile = np.array(pd.read_csv(oldfile, header=None))
    with open(newpath + newfile, "a", newline="") as csvFile:
        # 创建writer对象
        writer = csv.writer(csvFile)
        # 将前sampleNum条数据写入新文件
        for i in range(sampleNum):
            idx = indexList[i]
            l = MAX_SESS_LEN * idx
            r = MAX_SESS_LEN * (idx + 1)
            pld = oldfile[l:r]
            writer.writerows(pld)


def process(
    file: str,
    FLAG: int,
    stcPath_e: str,
    pldPath_e: str,
    stcPath_s: str,
    pldPath_s: str,
):
    """
    对文件进行采样

    Parameters
    ----------
    file : str
        采样文件

    FLAG : int
        标记需要采样的信息

    stcPath_e : str
        统计特征原始文件夹

    pldPath_e : str
        负载信息原始文件夹

    stcPath_s : str
        统计特征采样文件夹

    pldPath_s : str
        负载信息采样文件夹

    Returns
    -------
    None

    """
    # 采样数量, 对于攻击类别, 超过10000则采样10000, 不足10000则全部保留
    sampleNum = 10000

    label = file[0:-5]
    # Benign特殊处理
    if label == "Benign":
        sampleNum = 20000

    newfile = label + ".csv"

    print("process", label)

    statisticsFile = stcPath_e + file
    # 读取统计特征文件
    statisticsFile = np.array(pd.read_csv(statisticsFile))

    # 数据数量
    dataNum = statisticsFile.shape[0]
    # 索引列表
    indexList = [i for i in range(dataNum)]
    # 随机打乱顺序
    random.shuffle(indexList)
    # 需要采样的数量
    sampleNum = min(sampleNum, dataNum)

    if sampleNum == 0:
        return

    # 是否要对statistics采样
    if (FLAG >> 1) & 1:
        with open(stcPath_s + newfile, "a", newline="") as csvFile:
            # 创建writer对象
            writer = csv.writer(csvFile)
            for i in range(sampleNum):
                idx = indexList[i]
                stc = statisticsFile[idx]
                writer.writerow(stc)

    # 是否要对payload采样
    if FLAG & 1:
        # 处理负载数据
        payloadFile = pldPath_e + file
        writePLD(payloadFile, newfile, pldPath_s, sampleNum, indexList)


def sampleData(args):
    # 如果文件夹存在则删除
    if os.path.exists(args.sampleDataPath) == True:
        shutil.rmtree(args.sampleDataPath)
    # 创建采样数据文件夹
    os.mkdir(args.sampleDataPath)

    # 统计特征原始文件夹
    stcPath_e = args.extractDataPath + "statistics/"
    # 负载信息原始文件夹
    pldPath_e = args.extractDataPath + "payload/"
    # 统计特征采样文件夹
    stcPath_s = args.sampleDataPath + "statistics/"
    # 负载信息采样文件夹
    pldPath_s = args.sampleDataPath + "payload/"

    FLAG = args.flag
    # 是否要对statistics采样
    if (FLAG >> 1) & 1:
        # 创建统计特征文件夹(包括统计特征和包长分布)
        os.mkdir(stcPath_s)

    # 是否要对payload采样
    if FLAG & 1:
        # 创建负载信息文件夹
        os.mkdir(pldPath_s)

    # 文件名列表
    files = os.listdir(stcPath_e)
    # 依次处理文件
    for file in files:
        if file[0:6] != "Benign" and file[-5] != "0":
            continue
        process(
            file,
            FLAG,
            stcPath_e,
            pldPath_e,
            stcPath_s,
            pldPath_s,
        )
