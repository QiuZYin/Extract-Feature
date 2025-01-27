import config


class BasicPacketInfo:
    """数据包的统一格式"""

    def __init__(
        self,
        pktID,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        protocol,
        timeStamp,
        ipLength,
        headBytes,
        payloadBytes,
        payload,
        flags=None,
        sequence=None,
        acknowledgment=None,
        TCPWindow=None,
        packetLenMax=config.packetLenMax,
    ):
        # 数据包编号
        self.id = pktID
        # 源IP地址
        self.srcIP = srcIP
        # 目的IP地址
        self.dstIP = dstIP
        # 源端口
        self.srcPort = srcPort
        # 目的端口
        self.dstPort = dstPort
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = protocol
        # 时间戳
        self.timeStamp = timeStamp
        # IP数据包长度
        self.ipLength = ipLength
        # 传输层数据包头长度(UDP固定为8)
        self.headBytes = headBytes
        # 传输层负载长度
        self.payloadBytes = payloadBytes
        # 传输层负载
        self.payload = payload

        # 以下字段是TCP协议独有的
        # 控制位
        self.flags = flags
        # 序列号
        self.sequence = sequence
        # 确认号
        self.acknowledgment = acknowledgment
        # 窗口大小
        self.TCPWindow = TCPWindow
        # 数据包负载长度截取阈值
        self.packetLenMax = packetLenMax

        # 数据包所属流编号
        self.fwdFlowId = self.generateFlowId(True)
        self.bwdFlowId = self.generateFlowId(False)

        # 正反向上一个数据包到达的时间 getSubPayload() 用
        self.lastPktTime = [0, 0]

    def generateFlowId(self, direction: bool) -> str:
        """
        生成数据包的流ID

        Parameters
        ----------
        direction : bool
            方向,True为正向,False为反向

        Returns
        -------
        flowId : str
            流ID

        """
        if direction:
            flowId = (
                self.srcIP
                + "-"
                + str(self.srcPort)
                + "-"
                + self.dstIP
                + "-"
                + str(self.dstPort)
                + "-"
                + str(self.protocol)
            )
        else:
            flowId = (
                self.dstIP
                + "-"
                + str(self.dstPort)
                + "-"
                + self.srcIP
                + "-"
                + str(self.srcPort)
                + "-"
                + str(self.protocol)
            )
        return flowId

    def getPayloadSpcLen(self) -> list:
        """
        获取特定长度的数据包负载

        Parameters
        ----------
        None

        Returns
        -------
        payload : list
            数据包负载列表

        """
        # 截取下标为 0 - self.packetLenMax 的所有字节
        payload = [x for x in self.payload[0 : self.packetLenMax]]
        # 计算是否达到最长长度阈值
        res = self.packetLenMax - len(payload)
        # 如果没有达到则补零
        if res > 0:
            payload.extend([0 for i in range(res)])
        return payload

    def getSrcIP(self) -> str:
        return self.srcIP

    def getDstIP(self) -> str:
        return self.dstIP

    def getSrcPort(self) -> int:
        return self.srcPort

    def getDstPort(self) -> int:
        return self.dstPort

    def getProtocol(self) -> int:
        return self.protocol

    def getTimeStamp(self) -> int:
        return self.timeStamp

    def getIPLength(self) -> int:
        return self.ipLength

    def getHeadBytes(self) -> int:
        return self.headBytes

    def getPayloadBytes(self) -> int:
        return self.payloadBytes

    def getTCPWindow(self) -> int:
        return self.TCPWindow

    def getFwdFlowId(self) -> str:
        return self.fwdFlowId

    def hasFlagFIN(self) -> bool:
        return self.flags & 1

    def hasFlagSYN(self) -> bool:
        return (self.flags >> 1) & 1

    def hasFlagRST(self) -> bool:
        return (self.flags >> 2) & 1

    def hasFlagPSH(self) -> bool:
        return (self.flags >> 3) & 1

    def hasFlagACK(self) -> bool:
        return (self.flags >> 4) & 1

    def hasFlagURG(self) -> bool:
        return (self.flags >> 5) & 1

    def hasFlagECE(self) -> bool:
        return (self.flags >> 6) & 1

    def hasFlagCWR(self) -> bool:
        return (self.flags >> 7) & 1
