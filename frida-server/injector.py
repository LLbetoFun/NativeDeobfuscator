import frida
import sys
import os
import glob
import time
import threading
from typing import List, Optional, Callable

class JarInjector:
    def __init__(self):
        self.session = None
        self.scripts = []
        self.message_callback = None
        self.device = frida.get_local_device()
        self.pid = None
        self.running = False
        self.monitor_thread = None

    def set_message_callback(self, callback: Callable):
        """设置消息回调函数"""
        self.message_callback = callback

    def on_message(self, message, data):
        if message['type'] == 'send':
            msg = message['payload']
            if self.message_callback:
                self.message_callback(msg)
            else:
                print(f"[*] {msg}")
        elif message['type'] == 'error':
            print(f"[-] 脚本错误: {message}")

    def on_process_detached(self, session, reason):
        """进程分离时的回调"""
        print(f"\n[!] 进程已分离，原因: {reason}")
        self.running = False

    def load_scripts_from_dir(self, script_dir: str = "./script") -> List[str]:
        """从目录加载所有js文件"""
        if not os.path.exists(script_dir):
            print(f"[-] 脚本目录不存在: {script_dir}")
            return []

        js_files = glob.glob(os.path.join(script_dir, "*.js"))
        if not js_files:
            print(f"[-] 脚本目录为空: {script_dir}")
            return []

        scripts = []
        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    scripts.append(content)
                    print(f"[+] 加载脚本: {os.path.basename(js_file)}")
            except Exception as e:
                print(f"[-] 加载失败 {js_file}: {e}")
                return []

        return scripts

    def get_java_command(self, java_home: str = None) -> str:
        """
        获取Java命令路径
        如果java_home为None，则使用系统环境变量JAVA_HOME
        如果JAVA_HOME也不存在，则使用PATH中的java
        """
        if java_home:
            # 使用指定的Java home
            java_cmd = os.path.join(java_home, "bin", "java")
            if os.name == 'nt':  # Windows
                java_cmd += ".exe"

            if not os.path.exists(java_cmd):
                raise FileNotFoundError(f"指定的Java命令不存在: {java_cmd}")
            return java_cmd

        # 尝试使用系统环境变量JAVA_HOME
        system_java_home = os.environ.get('JAVA_HOME')
        if system_java_home:
            java_cmd = os.path.join(system_java_home, "bin", "java")
            if os.name == 'nt':
                java_cmd += ".exe"

            if os.path.exists(java_cmd):
                print(f"[*] 使用系统JAVA_HOME: {system_java_home}")
                return java_cmd
            else:
                print(f"[!] 系统JAVA_HOME存在但java命令不存在: {java_cmd}")

        # 最后尝试使用PATH中的java
        print("[*] 使用系统PATH中的java")
        return "java"

    def spawn_jar(self, jar_path: str, java_home: str = None, jvm_args: List[str] = None) -> int:
        """使用frida spawn模式启动jar包"""
        if not os.path.exists(jar_path):
            raise FileNotFoundError(f"Jar不存在: {jar_path}")

        # 获取Java命令
        java_cmd = self.get_java_command(java_home)

        # 构建命令
        cmd = [java_cmd]
        if jvm_args:
            cmd.extend(jvm_args)
        cmd.extend(["-jar", jar_path])

        print(f"[*] Spawn: {' '.join(cmd)}")

        # 使用frida的spawn启动进程（进程会处于挂起状态）
        self.pid = self.device.spawn(cmd)
        print(f"[+] 进程已创建 (挂起), PID: {self.pid}")

        return self.pid

    def monitor_process(self):
        """监控进程是否还在运行"""
        while self.running and self.pid:
            try:
                # 方法1: 使用enumerate_processes枚举所有进程并检查PID
                processes = self.device.enumerate_processes()
                process_exists = False

                for proc in processes:
                    if proc.pid == self.pid:
                        process_exists = True
                        break

                if not process_exists:
                    print(f"\n[*] 进程 {self.pid} 已结束")
                    self.running = False
                    break

                time.sleep(1)

            except Exception as e:
                print(f"\n[-] 监控异常: {e}")
                self.running = False
                break

    def inject_scripts(self, pid: int, scripts: List[str]) -> bool:
        """在进程恢复前注入脚本"""
        try:
            # 附加到挂起的进程
            self.session = self.device.attach(pid)

            # 设置进程分离回调
            self.session.on('detached', self.on_process_detached)

            # 注入所有脚本
            for i, script_code in enumerate(scripts):
                script = self.session.create_script(script_code)
                script.on('message', self.on_message)
                script.load()
                self.scripts.append(script)
                print(f"[+] 注入脚本 {i+1}/{len(scripts)}")

            return True

        except Exception as e:
            raise Exception(f"注入失败: {e}")

    def resume(self):
        """恢复进程执行"""
        if self.pid:
            self.device.resume(self.pid)
            print("[+] 进程已恢复执行")

    def wait_for_completion(self):
        """等待进程结束"""
        self.running = True

        # 启动监控线程
        self.monitor_thread = threading.Thread(target=self.monitor_process)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # 等待进程结束
        while self.running:
            time.sleep(0.5)

    def run(self, jar_path: str, script_dir: str = "./script",
            java_home: str = None, jvm_args: List[str] = None,
            wait: bool = True) -> bool:
        """
        Spawn模式：创建进程 -> 注入脚本 -> 恢复进程
        如果没有脚本则放弃启动

        Args:
            jar_path: Jar文件路径
            script_dir: 脚本目录路径
            java_home: Java安装目录
            jvm_args: JVM参数列表
            wait: 是否等待进程结束
        """
        # 1. 加载脚本，无脚本直接返回False
        scripts = self.load_scripts_from_dir(script_dir)
        if not scripts:
            print("[-] 没有可用的JS脚本，放弃启动")
            return False

        try:
            # 2. Spawn jar（进程挂起）
            pid = self.spawn_jar(jar_path, java_home, jvm_args)

            # 3. 注入脚本（进程仍在挂起状态）
            success = self.inject_scripts(pid, scripts)

            # 4. 恢复进程执行
            self.resume()

            if success:
                print(f"[✓] Spawn + 注入完成，已注入 {len(self.scripts)} 个脚本")

                # 5. 如果需要等待进程结束
                if wait:
                    self.wait_for_completion()

            return True

        except Exception as e:
            print(f"[-] 运行失败: {e}")
            # 如果失败，清理进程
            if self.pid:
                try:
                    self.device.kill(self.pid)
                except:
                    pass
            return False

    def stop(self):
        """停止所有"""
        self.running = False

        # 等待监控线程结束
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)

        # 卸载脚本
        for script in self.scripts:
            try:
                script.unload()
            except:
                pass

        # 分离会话
        if self.session:
            try:
                self.session.detach()
            except:
                pass

        # 终止进程
        if self.pid:
            try:
                self.device.kill(self.pid)
                print(f"[*] 进程 {self.pid} 已终止")
            except:
                pass


# ==================== 使用示例 ====================

def main():
    """使用示例"""

    JAR_PATH = "../workDir/SnakeGame-jnic.jar"
    SCRIPT_DIR = "./script"
    JAVA_HOME = None  # None表示使用系统JAVA_HOME或PATH中的java
    JVM_ARGS = ["-Xms1G", "-Xmx2G"]

    print("="*50)
    print("Frida Spawn模式注入工具")
    print("="*50)

    # 检查jar文件
    if not os.path.exists(JAR_PATH):
        print(f"[-] Jar文件不存在: {JAR_PATH}")
        jars = glob.glob("*.jar")
        if jars:
            print("[*] 可用的jar文件:")
            for j in jars:
                print(f"    - {j}")
        return

    # 检查脚本目录
    if not os.path.exists(SCRIPT_DIR):
        print(f"[-] 脚本目录不存在: {SCRIPT_DIR}")
        print("[*] 请创建script目录并放入.js文件")
        return

    js_files = glob.glob(os.path.join(SCRIPT_DIR, "*.js"))
    if not js_files:
        print(f"[-] 脚本目录为空: {SCRIPT_DIR}")
        print("[*] 请在script目录中放入.js文件")
        return

    # 显示Java环境信息
    if JAVA_HOME:
        print(f"[*] 使用指定的Java: {JAVA_HOME}")
    else:
        system_java = os.environ.get('JAVA_HOME')
        if system_java:
            print(f"[*] 使用系统JAVA_HOME: {system_java}")
        else:
            print("[*] 使用系统PATH中的java")

    # 创建注入器
    injector = JarInjector()

    def on_script_message(msg):
        print(f"[JS] {msg}")
    injector.set_message_callback(on_script_message)

    try:
        # wait=True表示等待进程结束，进程结束后程序会自动退出
        if injector.run(JAR_PATH, SCRIPT_DIR, JAVA_HOME, JVM_ARGS, wait=True):
            print("\n[*] 进程已结束，程序退出")
        else:
            print("[-] 启动失败")

    except KeyboardInterrupt:
        print("\n[*] 正在停止...")
    finally:
        injector.stop()
        print("[✓] 已清理")


# 不等待进程结束的示例
def no_wait_example():
    """不等待进程结束的示例"""
    injector = JarInjector()

    # wait=False表示不等待，立即返回
    injector.run(
        jar_path="minecraft_server.jar",
        wait=False
    )

    print("进程已在后台运行，按Enter停止")
    input()
    injector.stop()


if __name__ == "__main__":
    try:
        import frida
        print(f"[+] Frida版本: {frida.__version__}")
    except ImportError:
        print("[-] 请安装frida: pip install frida")
        sys.exit(1)

    try:
        device = frida.get_local_device()
        print(f"[+] 本地设备: {device}")
    except Exception as e:
        print(f"[-] 无法获取本地设备: {e}")
        sys.exit(1)

    main()