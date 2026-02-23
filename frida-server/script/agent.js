// Windows JVM JNIEnv 捕获器 - 合并优化版
// 保存所有捕获到的JNIEnv，按线程ID索引

// 主函数
function main() {
    console.log("\n" + "=".repeat(60));
    console.log("Windows JVM JNIEnv Capture - Merged Version");
    console.log("=".repeat(60) + "\n");

    // Hook所有JVM函数
    hookAllJVMFunctions().then(() => {
        console.log("\n[+] All hooks installed successfully!");

        // 定期显示状态
        var interval = setInterval(function() {
            if (g_jniEnvs.size > 0 && testLogs) {
                console.log("\n" + "-".repeat(40));
                console.log(`[Status] Captured ${g_jniEnvs.size} JNIEnv(s) for ${g_jniEnvs.size} thread(s)`);

                if (g_jniEnvs.size <= 5) {  // 如果线程不多，显示详情
                    getAllJNIEnvs();
                }
            }
        }, 10000);

        // 30分钟后停止
        setTimeout(() => clearInterval(interval), 1800000);
    });

    // 提供帮助信息
    console.log("\n[!] Available API functions:");
    console.log("    getJNIEnvForCurrentThread() - Get JNIEnv for current thread");
    console.log("    getAllJNIEnvs() - Show all captured JNIEnvs");
    console.log("    getAllJVMFunctions() - List all hooked JVM functions");
    console.log("    getJNIFunctionByOffset(env, offset) - Get JNI function by offset");
    console.log("    callJNIFindClass(env, className) - Example: Call FindClass");

    globalThis.getJNIEnv = getJNIEnvForCurrentThread;
    globalThis.getAllEnvs = getAllJNIEnvs;

    console.log("\n[✓] JNIEnvCapture API exposed globally");

    waitUntil(() => g_jniEnvs.size >= 1,hookJNIFunctions,500)
}

// 启动
setTimeout(main, 1000);

