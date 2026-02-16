import frida
import sys

def on_message(message, data):
    """处理来自JavaScript的消息"""
    if message['type'] == 'send':
        print(f"[*] 收到消息: {message['payload']}")
    else:
        print(f"[*] 收到其他消息: {message}")

def main():
    try:
        # 获取设备列表
        devices = frida.enumerate_devices()
        print("[+] Frida 环境配置正确!")
        print(f"[+] 检测到的设备数量: {len(devices)}")

        # 列出所有设备
        for i, device in enumerate(devices):
            print(f"   设备 {i+1}: {device.name} (类型: {device.type}, ID: {device.id})")

        # 获取本地设备并测试
        print("\n[*] 测试本地设备连接...")
        session = frida.get_local_device().attach(0)  # 0表示附加到自身进程
        print("[+] 成功附加到当前进程!")

        # 创建简单的脚本
        script_code = """
        console.log("[+] JavaScript 脚本执行成功!");
        send("Hello from JavaScript!");
        """

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()

        # 保持连接一小段时间
        import time
        time.sleep(1)

        script.unload()
        session.detach()

        print("\n[✓] 所有测试通过！你的Frida环境配置正确！")

    except Exception as e:
        print(f"[-] 测试失败: {e}")
        print("[!] 请检查Frida安装和配置")
        sys.exit(1)

if __name__ == "__main__":
    main()