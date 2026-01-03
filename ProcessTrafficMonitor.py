import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import time
import threading
from collections import deque
from ipaddress import ip_address
import gc

class ProcessTrafficMonitor:
    """
    Windows进程流量监视器
    - 监控指定进程在所有网卡上的TCP/UDP流量
    - 进程不存在时返回流量-1
    - 支持获取过去1-10秒的流量速率
    """

    MAX_HISTORY_SIZE = 1000  # 限制历史记录数量，防止内存无限增长

    def __init__(self, process_name: str):
        """
        创建进程流量监视器

        Args:
            process_name: 进程名称（如 "chrome.exe"）
        """
        self.process_name = process_name.lower()
        self.running = False
        self.process_exists = False
        self.target_pids = set()
        self.target_ports = set()

        # 线程安全的数据结构
        self._lock = threading.Lock()
        # 存储格式: (timestamp, direction, bytes) direction: 'up'/'down'
        self._traffic_history = deque(maxlen=self.MAX_HISTORY_SIZE)

        # 监控线程
        self._detect_thread = None
        self._capture_threads = []
        self._stats = {'total_upload': 0, 'total_download': 0}

    def _update_process_info(self):
        """更新进程PID和端口信息"""
        new_pids = set()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == self.process_name:
                    new_pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 获取所有PID使用的端口
        new_ports = set()
        if new_pids:
            for conn in psutil.net_connections(kind='inet'):
                if conn.pid in new_pids and conn.laddr:
                    new_ports.add(conn.laddr.port)

        with self._lock:
            self.target_pids = new_pids
            self.target_ports = new_ports
            self.process_exists = len(new_pids) > 0

        return self.process_exists

    def _detect_process_loop(self):
        """后台进程检测线程"""
        while self.running:
            self._update_process_info()
            time.sleep(2)  # 每2秒检测一次

    def _capture_on_interface(self, interface: str):
        """在指定网卡上捕获流量"""
        while self.running:
            try:
                # 如果进程不存在，暂停捕获
                if not self.process_exists:
                    time.sleep(1)
                    continue

                # 优化: 使用BPF过滤和store=0防止内存泄漏
                scapy.sniff(
                    iface=interface,
                    filter="tcp or udp",  # BPF过滤，只捕获TCP/UDP
                    prn=self._packet_handler,
                    store=0,  # 关键: 不存储数据包，防止Scapy内存泄漏
                    timeout=5,  # 设置超时，定期检查running状态
                    quiet=True  # 减少输出
                )
            except Exception:
                # 网卡异常时重试
                time.sleep(1)

    def _packet_handler(self, packet):
        """处理捕获的数据包"""
        try:
            if not self.process_exists or IP not in packet:
                return

            # 快速判断: 如果没有目标端口，直接返回
            with self._lock:
                if not self.target_ports:
                    return

            # 提取端口
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            else:
                return

            # 判断方向
            with self._lock:
                is_outgoing = src_port in self.target_ports
                is_incoming = dst_port in self.target_ports

            if not (is_outgoing or is_incoming):
                return

            # 记录流量
            timestamp = time.time()
            size = len(packet[IP])
            direction = 'up' if is_outgoing else 'down'

            with self._lock:
                self._traffic_history.append((timestamp, direction, size))
                if is_outgoing:
                    self._stats['total_upload'] += size
                else:
                    self._stats['total_download'] += size

        except Exception:
            # 忽略解析错误，防止内存泄漏
            pass
        finally:
            # 显式删除packet对象
            del packet

    def _clear_old_records(self):
        """清理超过10秒的旧记录"""
        cutoff_time = time.time() - 10
        with self._lock:
            # 移除旧记录
            while self._traffic_history and self._traffic_history[0][0] < cutoff_time:
                self._traffic_history.popleft()

    def start(self):
        """启动流量监控"""
        if self.running:
            return

        self.running = True

        # 1. 初始化进程检测
        self._update_process_info()

        # 2. 启动进程检测线程
        self._detect_thread = threading.Thread(target=self._detect_process_loop, daemon=True)
        self._detect_thread.start()

        # 3. 获取所有网卡并启动捕获线程
        try:
            # 尝试获取所有网卡名称
            interfaces = [iface['name'] for iface in scapy.get_if_list()]
        except:
            # 回退到默认网卡
            interfaces = [scapy.conf.iface]

        for iface in interfaces:
            thread = threading.Thread(
                target=self._capture_on_interface,
                args=(iface,),
                daemon=True
            )
            thread.start()
            self._capture_threads.append(thread)

        # 4. 启动清理线程
        def cleanup_loop():
            while self.running:
                time.sleep(5)  # 每5秒清理一次
                self._clear_old_records()
                # 强制垃圾回收
                gc.collect()

        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()

        time.sleep(1)  # 等待线程启动

    def stop(self):
        """停止流量监控"""
        if not self.running:
            return

        self.running = False

        # 等待线程结束
        if self._detect_thread:
            self._detect_thread.join(timeout=2)

        for thread in self._capture_threads:
            thread.join(timeout=2)

        # 清空数据
        with self._lock:
            self._traffic_history.clear()
            self.target_pids.clear()
            self.target_ports.clear()

        gc.collect()

    def get_traffic(self, seconds: int) -> tuple[float, float]:
        """
        获取过去指定时间内的流量速率

        Args:
            seconds: 时间窗口(1-10秒)，小于1按1秒，大于10报错

        Returns:
            (upload_kbps, download_kbps): 进程不存在时返回(-1, -1)

        Raises:
            ValueError: seconds参数超出范围(>10)
        """
        # 参数验证
        if seconds < 1:
            seconds = 1
        elif seconds > 10:
            raise ValueError("时间窗口不能超过10秒")

        # 检查进程是否存在
        if not self.process_exists:
            return -1.0, -1.0

        # 清理旧数据
        self._clear_old_records()

        # 计算时间窗口
        current_time = time.time()
        start_time = current_time - seconds

        upload_bytes = 0
        download_bytes = 0

        # 统计窗口内流量
        with self._lock:
            # 倒序遍历，更早的数据在后面
            for record in reversed(self._traffic_history):
                timestamp, direction, size = record

                if timestamp < start_time:
                    break

                if direction == 'up':
                    upload_bytes += size
                else:
                    download_bytes += size

        # 计算速率 (KB/s)
        upload_rate = upload_bytes / seconds / 1024
        download_rate = download_bytes / seconds / 1024

        return upload_rate, download_rate

    def is_monitoring(self) -> bool:
        """检查是否正在监控中"""
        return self.running and self.process_exists

    def get_stats(self) -> dict:
        """获取总流量统计"""
        with self._lock:
            return {
                'process_name': self.process_name,
                'process_exists': self.process_exists,
                'pids': list(self.target_pids),
                'ports': list(self.target_ports),
                'total_upload_mb': self._stats['total_upload'] / 1024 / 1024,
                'total_download_mb': self._stats['total_download'] / 1024 / 1024,
                'history_size': len(self._traffic_history)
            }