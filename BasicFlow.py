from utils import SummaryStatistics, PacketLengthDistribution
from BasicPacketInfo import BasicPacketInfo
from FlowFeature import FlowFeature


class BasicFlow:
    """会话流的统一格式"""

    def __init__(
        self,
        packet: BasicPacketInfo,
        activityTimeout=5000000,
        subFlowTimeout=1000000,
        packetNumMax=16,
        packetLenMax=128,
    ):
        """流标识信息"""
        # 流ID
        self.flowId = None
        """流基本信息"""
        # 源IP地址
        self.srcIP = None
        # 源端口
        self.srcPort = 0
        # 目的IP地址
        self.dstIP = None
        # 目的端口
        self.dstPort = 0
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = 0
        """流时间信息"""
        # 流开始时间戳(us)
        self.flowStartTS = 0
        # 流结束时间戳(us)
        self.flowEndTS = 0

        # 正向数据包最近出现的时间戳(us)
        self.fwdLastTS = 0
        # 反向数据包最近出现的时间戳(us)
        self.bwdLastTS = 0

        # 子流时间戳(us)
        self.subFlowLastTS = 0
        # 子流个数
        self.subFlowcnt = 0
        # 子流超时(-1表示需要被初始化)
        self.subFlowTimeout = -1

        # 流开始活动时间戳(us)
        self.startActiveTS = 0
        # 流结束活动时间戳(us)
        self.endActiveTS = 0
        # 流活动超时
        self.activityTimeout = 0

        # 数据包间隔时间列表(ms)
        self.flowIAT = SummaryStatistics()
        # 正向数据包间隔时间列表(ms)
        self.forwardIAT = SummaryStatistics()
        # 反向数据包间隔时间列表(ms)
        self.backwardIAT = SummaryStatistics()
        # 流活动时间列表(ms)
        self.flowActive = SummaryStatistics()
        # 流空闲时间列表(ms)
        self.flowIdle = SummaryStatistics()
        """数据包长度信息"""
        # 正向数据包头长度列表
        self.fwdHeadStats = SummaryStatistics()
        # 反向数据包头长度列表
        self.bwdHeadStats = SummaryStatistics()

        # 正向数据包负载长度列表(负载不为0)
        self.fwdPktPldStats = SummaryStatistics()
        # 反向数据包负载长度列表(负载不为0)
        self.bwdPktPldStats = SummaryStatistics()
        # 数据包负载长度列表(负载不为0)
        self.flowPldStats = SummaryStatistics()
        # 正向IP数据包包长分布
        self.fwdPktLenDistribution = PacketLengthDistribution()
        # 反向IP数据包包长分布
        self.bwdPktLenDistribution = PacketLengthDistribution()

        """TCP标志信息"""
        # 带有FIN的数据包数量
        self.FINcnt = 0
        # 带有SYN的数据包数量
        self.SYNcnt = 0
        # 带有RST的数据包数量
        self.RSTcnt = 0
        # 带有PSH的数据包数量
        self.PSHcnt = 0
        # 带有ACK的数据包数量
        self.ACKcnt = 0
        # 带有URG的数据包数量
        self.URGcnt = 0
        # 带有ECE的数据包数量
        self.ECEcnt = 0
        # 带有CWR的数据包数量
        self.CWRcnt = 0

        # 正向数据包中设置PSH标志的数量(UDP为0)
        self.fwdPSHcnt = 0
        # 反向数据包中设置PSH标志的数量(UDP为0)
        self.bwdPSHcnt = 0
        # 正向数据包中设置URG标志的数量(UDP为0)
        self.fwdURGcnt = 0
        # 反向数据包中设置URG标志的数量(UDP为0)
        self.bwdURGcnt = 0
        """部分统计特征"""
        # 正向的初始TCP窗口大小(UDP为0)
        self.fwdInitWinBytes = 0
        # 反向的初始TCP窗口大小(UDP为0)
        self.bwdInitWinBytes = 0
        """会话流统计特征类"""
        # 基于流的统计特征
        self.features = FlowFeature()
        """会话流传输层负载信息"""
        # 会话流数据包负载信息
        self.payloads = []
        """根据参数以及第一个数据包 初始化部分信息"""
        self.srcIP = packet.getSrcIP()
        self.srcPort = packet.getSrcPort()
        self.dstIP = packet.getDstIP()
        self.dstPort = packet.getDstPort()

        # 设置流ID
        self.flowId = packet.getFwdFlowId()
        self.protocol = packet.getProtocol()

        # 获取数据包时间戳
        currentTS = packet.getTimeStamp()
        # 设置会话流开始时间等信息
        self.flowStartTS = currentTS
        self.flowEndTS = currentTS
        self.startActiveTS = currentTS
        self.endActiveTS = currentTS
        self.subFlowLastTS = currentTS

        # 设置阈值
        self.subFlowTimeout = subFlowTimeout  # 子流超时阈值
        self.activityTimeout = activityTimeout  # 流活动超时阈值
        self.packetNumMax = packetNumMax  # 截取的最大数据包个数阈值
        self.packetLenMax = packetLenMax  # 每个数据包截取的最大字节长度阈值

    def addPacket(self, packet: BasicPacketInfo) -> None:
        """
        向会话流中添加数据包

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        Returns
        -------
        None

        """

        # 获取数据包时间戳
        currentTS = packet.getTimeStamp()
        # 获取负载长度
        pktPLBs = packet.getPayloadBytes()

        # 如果是正向流
        if self.srcIP == packet.getSrcIP():
            # 方向
            direction = 0
            # 更新正向数据包头长度
            self.fwdHeadStats.addValue(packet.getHeadBytes())
            self.fwdPktLenDistribution.addValue(packet.getIPLength())

            # 如果是TCP包
            if self.protocol == 6:
                # 更新正向TCP标志
                self.fwdPSHcnt += packet.hasFlagPSH()
                self.fwdURGcnt += packet.hasFlagURG()
                # 如果是第一个正向数据包
                if self.fwdHeadStats.getN() == 1:
                    # 设置正向的初始TCP窗口大小
                    self.fwdInitWinBytes = packet.getTCPWindow()

            # 如果负载不为空
            if pktPLBs > 0:
                # 更新正向数据包负载长度
                self.fwdPktPldStats.addValue(pktPLBs)

            # 更新正向数据包间隔时间
            self.forwardIAT.addValue((currentTS - self.fwdLastTS) / 1000)

            # 更新正向数据包当前时间
            self.fwdLastTS = currentTS

        # 如果是反向流
        elif self.srcIP == packet.getDstIP():
            # 方向
            direction = 1
            # 更新反向数据包头长度
            self.bwdHeadStats.addValue(packet.getHeadBytes())
            self.bwdPktLenDistribution.addValue(packet.getIPLength())

            # 如果是TCP包
            if self.protocol == 6:
                # 更新反向TCP标志
                self.bwdPSHcnt += packet.hasFlagPSH()
                self.bwdURGcnt += packet.hasFlagURG()
                # 如果是第一个反向数据包
                if self.bwdHeadStats.getN() == 1:
                    # 设置反向的初始TCP窗口大小
                    self.bwdInitWinBytes = packet.getTCPWindow()

            # 如果负载不为空
            if pktPLBs > 0:
                # 更新反向数据包负载长度
                self.bwdPktPldStats.addValue(pktPLBs)

            # 更新反向数据包间隔时间
            self.backwardIAT.addValue((currentTS - self.bwdLastTS) / 1000)

            # 更新反向数据包当前时间
            self.bwdLastTS = currentTS

        # 间隔时间
        intervalTime = (currentTS - self.flowEndTS) / 1000
        # 更新会话流数据包间隔时间
        self.flowIAT.addValue(intervalTime)

        # 如果负载不为空
        if pktPLBs > 0:
            # 更新会话流数据包负载长度
            self.flowPldStats.addValue(pktPLBs)

        if len(self.payloads) < self.packetNumMax:
            # 更新会话流数据包负载
            self.payloads.append(packet.getPayloadSpcLen())

        # 更新流结束时间
        self.flowEndTS = currentTS

        # 如果是TCP包
        if self.protocol == 6:
            # 更新标志信息
            self.updateFlags(packet)

        # 更新子流信息
        self.updateSubflows(packet)
        # 更新流活动空闲信息
        self.updateActIdleTime(packet)

    def updateFlags(self, packet: BasicPacketInfo) -> None:
        """
        更新数据包TCP标志数量

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        Returns
        -------
        None

        """
        self.FINcnt += packet.hasFlagFIN()
        self.SYNcnt += packet.hasFlagSYN()
        self.RSTcnt += packet.hasFlagRST()
        self.PSHcnt += packet.hasFlagPSH()
        self.ACKcnt += packet.hasFlagACK()
        self.URGcnt += packet.hasFlagURG()
        self.ECEcnt += packet.hasFlagECE()
        self.CWRcnt += packet.hasFlagCWR()

    def updateSubflows(self, packet: BasicPacketInfo) -> None:
        """
        更新子流时间戳和个数

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        Returns
        -------
        None

        """

        # 当前时间戳
        currentTS = packet.getTimeStamp()
        # 和上一个数据包的间隔时间
        idleTime = currentTS - self.subFlowLastTS
        # 如果超过阈值
        if idleTime > self.subFlowTimeout:
            # 子流数量加一
            self.subFlowcnt += 1
        # 更新子流时间戳
        self.subFlowLastTS = currentTS

    def updateActIdleTime(self, packet: BasicPacketInfo) -> None:
        """
        统计流活动时间和空闲时间

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        Returns
        -------
        None

        """

        # 当前时间戳
        currentTS = packet.getTimeStamp()
        # 和上一个数据包的间隔时间(即空闲时间)
        idleTime = currentTS - self.endActiveTS
        # 如果超过阈值
        if idleTime > self.activityTimeout:
            # 更新流空闲时间
            self.flowIdle.addValue(idleTime / 1000)

            # 计算流活动时间
            activeTime = self.endActiveTS - self.startActiveTS
            # 如果活动时间大于0(即上一个活动区间的数据包个数大于1)
            if activeTime > 0:
                # 更新流活动时间
                self.flowActive.addValue(activeTime / 1000)

            # 更新流活动开始时间
            self.startActiveTS = currentTS

        # 更新流活动结束时间
        self.endActiveTS = currentTS

    def endSession(self) -> None:
        """
        结束会话,更新流活动时间

        Parameters
        ----------
        None

        Returns
        -------
        None

        """

        # 计算活动时间
        activeTime = self.endActiveTS - self.startActiveTS
        # 如果活动时间大于0
        if activeTime > 0:
            # 更新流活动时间
            self.flowActive.addValue(activeTime / 1000)

    def generateFlowFeatures(self) -> list:
        """
        生成会话流的特征

        Parameters
        ----------
        None

        Returns
        -------
        featureValue : list
            会话流的统计特征

        """
        """流基本信息"""
        # self.features.flowId = self.flowId
        # self.features.srcIP = self.srcIP
        self.features.srcPort = self.srcPort
        # self.features.dstIP = self.dstIP
        self.features.dstPort = self.dstPort
        self.features.protocol = self.protocol

        # """流时间信息"""
        # # 流开始时间(s)
        # self.features.startTime = self.flowStartTS / 1000000
        # # 流最近出现时间(s)
        # self.features.endTime = self.flowEndTS / 1000000
        # 流持续时间(s)
        if self.flowEndTS == self.flowStartTS:
            return None

        self.features.flowDuration = (self.flowEndTS - self.flowStartTS) / 1000000

        """数据包个数,首部字节数相关特征"""
        # 正向流首部长度信息
        self.features.fwdPktNum = self.fwdHeadStats.getN()
        self.features.fwdHeadByteMean = self.fwdHeadStats.getMean()
        self.features.fwdHeadByteStd = self.fwdHeadStats.getStd()

        # 反向流首部长度信息
        self.features.bwdPktNum = self.bwdHeadStats.getN()
        self.features.bwdHeadByteMean = self.bwdHeadStats.getMean()
        self.features.bwdHeadByteStd = self.bwdHeadStats.getStd()

        """数据包负载字节数相关特征"""
        # 会话流负载长度信息
        self.features.flowPktNumWithPld = self.flowPldStats.getN()
        self.features.flowPldByteSum = self.flowPldStats.getSum()
        self.features.flowPldByteMax = self.flowPldStats.getMax()
        self.features.flowPldByteMin = self.flowPldStats.getMin()
        self.features.flowPldByteMean = self.flowPldStats.getMean()
        self.features.flowPldByteStd = self.flowPldStats.getStd()

        # 正向流负载长度信息
        self.features.fwdPktNumWithPld = self.fwdPktPldStats.getN()
        self.features.fwdPldByteSum = self.fwdPktPldStats.getSum()
        self.features.fwdPldByteMax = self.fwdPktPldStats.getMax()
        self.features.fwdPldByteMin = self.fwdPktPldStats.getMin()
        self.features.fwdPldByteMean = self.fwdPktPldStats.getMean()
        self.features.fwdPldByteStd = self.fwdPktPldStats.getStd()

        # 反向流负载长度信息
        self.features.bwdPktNumWithPld = self.bwdPktPldStats.getN()
        self.features.bwdPldByteSum = self.bwdPktPldStats.getSum()
        self.features.bwdPldByteMax = self.bwdPktPldStats.getMax()
        self.features.bwdPldByteMin = self.bwdPktPldStats.getMin()
        self.features.bwdPldByteMean = self.bwdPktPldStats.getMean()
        self.features.bwdPldByteStd = self.bwdPktPldStats.getStd()

        """流速相关特征"""
        # 速率相关特征
        self.features.calRate()

        """间隔时间相关特征"""
        """这里把第一个值删除的原因是, 第一个值计算的是 第一个数据包的时间戳 与 初始时间戳 之间的差值"""
        # 会话流间隔时间
        self.flowIAT.delete(0)
        self.features.flowIatMax = self.flowIAT.getMax()
        self.features.flowIatMin = self.flowIAT.getMin()
        self.features.flowIatMean = self.flowIAT.getMean()
        self.features.flowIatStd = self.flowIAT.getStd()

        # 正向流间隔时间
        self.forwardIAT.delete(0)
        self.features.fwdIatMax = self.forwardIAT.getMax()
        self.features.fwdIatMin = self.forwardIAT.getMin()
        self.features.fwdIatMean = self.forwardIAT.getMean()
        self.features.fwdIatStd = self.forwardIAT.getStd()

        # 反向流间隔时间
        self.backwardIAT.delete(0)
        self.features.bwdIatMax = self.backwardIAT.getMax()
        self.features.bwdIatMin = self.backwardIAT.getMin()
        self.features.bwdIatMean = self.backwardIAT.getMean()
        self.features.bwdIatStd = self.backwardIAT.getStd()

        """TCP标志相关特征"""
        self.features.FINcnt = self.FINcnt
        self.features.SYNcnt = self.SYNcnt
        self.features.RSTcnt = self.RSTcnt
        self.features.PSHcnt = self.PSHcnt
        self.features.ACKcnt = self.ACKcnt
        self.features.URGcnt = self.URGcnt
        self.features.ECEcnt = self.ECEcnt
        self.features.CWRcnt = self.CWRcnt

        self.features.fwdPSHcnt = self.fwdPSHcnt
        self.features.bwdPSHcnt = self.bwdPSHcnt
        self.features.fwdURGcnt = self.fwdURGcnt
        self.features.bwdURGcnt = self.bwdURGcnt

        """初始窗口大小"""
        self.features.fwdInitWinBytes = self.fwdInitWinBytes
        self.features.bwdInitWinBytes = self.bwdInitWinBytes

        """子流相关特征"""
        self.features.calSubFlow(self.subFlowcnt)

        """流活动-空闲相关特征"""
        # 会话流活动时间信息
        self.features.flowActNum = self.flowActive.getN()
        self.features.flowActSum = self.flowActive.getSum()
        self.features.flowActMax = self.flowActive.getMax()
        self.features.flowActMin = self.flowActive.getMin()
        self.features.flowActMean = self.flowActive.getMean()
        self.features.flowActStd = self.flowActive.getStd()

        # 会话流空闲时间信息
        self.features.flowIdleNum = self.flowIdle.getN()
        self.features.flowIdleSum = self.flowIdle.getSum()
        self.features.flowIdleMax = self.flowIdle.getMax()
        self.features.flowIdleMin = self.flowIdle.getMin()
        self.features.flowIdleMean = self.flowIdle.getMean()
        self.features.flowIdleStd = self.flowIdle.getStd()

        self.features.fwdLenDist = self.fwdPktLenDistribution.returnValue()
        self.features.bwdLenDist = self.bwdPktLenDistribution.returnValue()

        # 通过FlowFeature类返回特征
        return self.features.returnFeature()

    def getSrcIP(self) -> str:
        """返回源IP"""
        return self.srcIP

    def getDstIP(self) -> str:
        """返回目的IP"""
        return self.dstIP

    def getFlowID(self) -> str:
        """返回流ID"""
        return self.flowId

    def getPayloads(self) -> list:
        """返回会话流数据包负载信息"""
        # 如果数据包个数不足self.packetNumMax, 则补零
        res = self.packetNumMax - len(self.payloads)
        if res > 0:
            self.payloads.extend(
                [[0 for i in range(self.packetLenMax)] for j in range(res)]
            )
        return self.payloads
