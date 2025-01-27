import csv
import numpy as np


class IdGenerator:
    """为每个数据包生成唯一的ID"""

    def __init__(self):
        self.id = 0

    def nextId(self):
        self.id += 1
        return self.id

    def nowId(self):
        return self.id


class SummaryStatistics:
    """统计值类"""

    def __init__(self):
        self.value = []  # 保存值
        self.N = 0  # 保存个数

    def addValue(self, newValue):
        self.value.append(newValue)
        self.N += 1

    def getN(self):
        return self.N

    def getSum(self):
        if self.N == 0:
            return 0
        return sum(self.value)

    def getMax(self):
        if self.N == 0:
            return 0
        return max(self.value)

    def getMin(self):
        if self.N == 0:
            return 0
        return min(self.value)

    def getMean(self):
        if self.N == 0:
            return 0
        return np.mean(self.value)

    def getStd(self):
        if self.N == 0:
            return 0
        return np.std(self.value)

    def getVar(self):
        if self.N == 0:
            return 0
        return np.var(self.value)

    def delete(self, idx):
        """删除指定位置的值"""
        if len(self.value) > idx:
            del self.value[idx]
            self.N -= 1


class PacketLengthDistribution:
    """IP数据包长度分布"""

    def __init__(self) -> None:
        """将数据包的长度映射到0-149之间"""
        self.cnt = [0 for i in range(150)]
        self.N = 0

    def addValue(self, value: int) -> None:
        """
        正常IP数据包长度在46-1500之间, 但是有些数据包的长度会超过1500,
        因此需要通过一定规则进行映射

        Parameters
        ----------
        value : int
            新增数据值

        Returns
        -------
        None

        """
        self.N += 1
        # 如果长度小于40, 则映射到0
        if value < 40:
            self.cnt[0] += 1
        # 如果长度在40-1500之间, 则映射到1-147之间
        elif value <= 1500:
            i = value // 10 - 3
            self.cnt[i] += 1
        # 如果长度在1501-2960之间, 则映射到148
        elif value <= 2960:
            self.cnt[148] += 1
        # 如果长度大于2960, 则映射到149
        else:
            self.cnt[149] += 1

    def returnValue(self) -> list:
        """返回数据包长度分布列表"""
        return self.cnt


class OutputInfo:
    def __init__(self, extractDataPath, featureName):
        self.info = {}
        self.stcDataPath = extractDataPath + "statistics/"
        self.pldDataPath = extractDataPath + "payload/"
        self.featureName = featureName

    def check(self, label):
        if label not in self.info:
            statisticsFile = self.stcDataPath + label + "0.csv"
            payloadFile = self.pldDataPath + label + "0.csv"
            # 创建并清空文件
            with open(statisticsFile, "w", newline="") as csvFile:
                # 创建writer对象
                writer = csv.writer(csvFile)
                # 写入特征名称
                writer.writerow(self.featureName)

            self.info[label] = [0, 0, statisticsFile, payloadFile]

    def getFile(self, label):
        self.info[label][1] += 1
        if self.info[label][1] > 100000:
            self.info[label][0] += 1
            self.info[label][1] = 1
            idx = self.info[label][0]
            statisticsFile = self.stcDataPath + label + str(idx) + ".csv"
            payloadFile = self.pldDataPath + label + str(idx) + ".csv"
            # 创建并清空文件
            with open(statisticsFile, "w", newline="") as csvFile:
                # 创建writer对象
                writer = csv.writer(csvFile)
                # 写入特征名称
                writer.writerow(self.featureName)

            self.info[label][2] = statisticsFile
            self.info[label][3] = payloadFile

        return self.info[label][2], self.info[label][3]
