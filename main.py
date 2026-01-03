import time

from ProcessTrafficMonitor import ProcessTrafficMonitor


def onStart():
    print("监控已启动")

def onAct():
    print("监控正在活动")


def onInAct():
    print("监控停止活动")


def onStop():
    print("监控已停止")

# ==================== 使用示例 ====================
if __name__ == "__main__":
    # 创建监控器
    monitor = ProcessTrafficMonitor("AtHomeVideoStreamer.exe")
    status=0

    try:
        # 启动监控
        monitor.start()
        print(f"[+] 开始监控进程: {monitor.process_name}")

        while True:
            time.sleep(1)
            up,down=monitor.get_traffic(2)
            if up<0:
                if status!=0:
                    status=0
                    onStop()
                    continue

            if up>=20:
                if status!=2:
                    status=2
                    onAct()

            if (up<20)&(up>=0):
                if status==2:
                    status = 1
                    onInAct()
                elif status==0:
                    status=1
                    onStart()


    except KeyboardInterrupt:
        print("\n[!] 用户中断")

    finally:
        # 停止监控并清理
        monitor.stop()
        print("[+] 程序退出")
