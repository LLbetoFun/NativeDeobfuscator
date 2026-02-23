// 主函数：Hook所有JVM函数
function hookAllJVMFunctions() {
    return new Promise((resolve) => {
        // 1. 找到jvm.dll
        var jvmModule = Process.getModuleByName("jvm.dll");
        if (!jvmModule) {
            console.error("[-] jvm.dll not found!");
            console.log("[*] Trying to find JVM module by scanning...");

            // 尝试扫描所有模块找到可能的JVM实现
            var modules = Process.enumerateModules();
            for (var mod of modules) {
                if (mod.name.toLowerCase().includes("jvm") ||
                    mod.name.toLowerCase().includes("java")) {
                    console.log("[+] Found potential JVM module:", mod.name, "at", mod.base);
                    jvmModule = mod;
                    break;
                }
            }

            if (!jvmModule) {
                console.error("[-] No JVM module found!");
                return;
            }
        }

        console.log("[+] JVM module:", jvmModule.name, "loaded at:", jvmModule.base);

        // 2. 枚举所有导出函数
        var exports = jvmModule.enumerateExports();
        console.log("[*] Total exports in module:", exports.length);

        // 3. 收集匹配的函数
        var functionsToHook = findJVMFunctionsToHook(exports);

        // 4. Hook所有找到的函数
        hookFoundFunctions(functionsToHook);

        // 5. 打印统计信息
        console.log("\n[+] Hook Summary:");
        console.log("    Total JVM functions hooked:", Object.keys(g_jvmFunctions).length);
        console.log("    Categories:");

        var categories = {};
        for (var name in g_jvmFunctions) {
            var prefix = name.split('_')[0];
            categories[prefix] = (categories[prefix] || 0) + 1;
        }
        for (var cat in categories) {
            console.log(`      ${cat}: ${categories[cat]} functions`);
        }

        resolve();
    });
}

// 查找要Hook的JVM函数
function findJVMFunctionsToHook(exports) {
    var functionsToHook = [];
    var foundNames = new Set();

    console.log("\n[*] Scanning for JVM functions to hook...");

    for (var i = 0; i < exports.length; i++) {
        var exp = exports[i];
        var name = exp.name;
        var address = exp.address;

        // 检查是否匹配预定义的函数列表
        for (var j = 0; j < JVM_FUNCTIONS_TO_HOOK.length; j++) {
            var target = JVM_FUNCTIONS_TO_HOOK[j];
            if (name.indexOf(target) !== -1 && !foundNames.has(name)) {
                functionsToHook.push({
                    name: name,
                    address: address,
                    type: 'exact'
                });
                foundNames.add(name);
                console.log(`  [EXACT] ${name} -> ${address}`);
                break;
            }
        }

        // 如果没找到，检查额外模式
        if (!foundNames.has(name)) {
            for (var k = 0; k < EXTRA_PATTERNS.length; k++) {
                var pattern = EXTRA_PATTERNS[k];
                if (name.indexOf(pattern) !== -1) {
                    functionsToHook.push({
                        name: name,
                        address: address,
                        type: 'pattern'
                    });
                    foundNames.add(name);
                    console.log(`  [PATTERN] ${name} -> ${address}`);
                    break;
                }
            }
        }
    }

    console.log(`[*] Found ${functionsToHook.length} JVM functions to hook`);
    return functionsToHook;
}

// Hook所有找到的函数
// Hook所有找到的函数 - 修复版本
function hookFoundFunctions(functionsToHook) {
    for (var i = 0; i < functionsToHook.length; i++) {
        var func = functionsToHook[i];

        // 保存函数地址
        g_jvmFunctions[func.name] = func.address;

        // 使用闭包捕获函数名
        (function(functionName, functionAddress) {
            Interceptor.attach(functionAddress, {
                onEnter: function(args) {
                    var tid = Process.getCurrentThreadId();
                    // 安全检查
                    try {

                        var potentialEnv = args[0];

                        // JVM函数第一个参数应该是JNIEnv*
                        if (potentialEnv && !potentialEnv.isNull()) {
                            if (isValidJNIEnv(potentialEnv)) {
                                if (!g_jniEnvs.has(tid)) {
                                    g_jniEnvs.set(tid, {
                                        env: potentialEnv,
                                        functionName: functionName,  // 使用闭包变量
                                        timestamp: Date.now()
                                    });

                                    setTimeout((function (){
                                        console.log(`\n[!!!] Captured JNIEnv from ${functionName} for thread ${tid}:`, potentialEnv);

                                        verifyJNIEnv(potentialEnv, tid)
                                    }),300)
                                }
                            }
                        }
                        if(testLogs) logFunctionCall(functionName, args, tid);  // 使用闭包变量

                    } catch (e) {
                        // 静默处理，避免干扰
                        // console.log(`[Debug] Error in ${functionName}:`, e.message);
                    }
                }
            });
        })(func.name, func.address);
    }
}

// 验证JNIEnv是否有效
function isValidJNIEnv(env) {

    if (env.isNull()) return false;

    try {
        // JNIEnv 应该指向一个函数表
        var funcTable = env.readPointer();
        if (!funcTable || funcTable.isNull())
        {
            console.log("funcTable is null")
            return false;
        }

        // 读取第一个函数指针
        var firstFunc = funcTable.add(32).readPointer();
        if (!firstFunc || firstFunc.isNull()) {
            console.log("funcTable's 1st func is null")

            return false;
        }
        // 检查是否在jvm模块中

        return true;
    } catch (e) {
        return false;
    }
}

// 验证JNIEnv详情
function verifyJNIEnv(env, tid) {
    console.log(`[+] Verifying JNIEnv for thread ${tid}...`);

    try {
        var funcTable = env.readPointer();
        console.log(`    Function table at:`, funcTable);

        // 读取前几个JNI函数
        console.log(`    First few JNI functions:`);
        for (var i = 0; i < 5; i++) {
            var funcPtr = funcTable.add(i * Process.pointerSize).readPointer();
            var module = Process.findModuleByAddress(funcPtr);
            console.log(`      [${i}] ${funcPtr} (${module ? module.name : 'unknown'})`);
        }

        // 尝试调用GetVersion
        checkNIVersion(env);

    } catch (e) {
        console.log(`    Error verifying JNIEnv:`, e.message);
    }
}

// 测试JNI调用
function checkNIVersion(env) {
    try {
        var functions = env.readPointer();
        var GetVersion = functions.add(32).readPointer();

        var JNI_GetVersion = new NativeFunction(GetVersion, 'int', ['pointer']);
        var version = JNI_GetVersion(env);

        console.log(`    JNI GetVersion returned: 0x${version.toString(16)}`);

        var jniVersion = version >> 16;  // 右移16位得到主版本号

        var versionMap = {
            1: "JNI 1.1",
            2: "JNI 1.2",
            3: "JNI 1.3",
            4: "JNI 1.4",
            5: "JNI 1.5",
            6: "JNI 1.6",
            7: "JNI 1.7",
            8: "JNI 1.8",
            9: "JNI 9",
            10: "JNI 10",
            11: "JNI 11",
            12: "JNI 12",
            13: "JNI 13",
            14: "JNI 14",
            15: "JNI 15",
            16: "JNI 16",
            17: "JNI 17",
            18: "JNI 18",
            19: "JNI 19",
            20: "JNI 20",
            21: "JNI 21 (Java 11/12/13/14/15/16/17)",
            22: "JNI 22 (Java 18+)"
        };

        if (versionMap[jniVersion]) {
            console.log(`    ${versionMap[jniVersion]}`);
        } else {
            console.log(`    Unknown JNI version: ${jniVersion} (0x${version.toString(16)})`);
        }

        // 显示详细版本信息
        console.log(`    Version details: major=${jniVersion}, raw=0x${version.toString(16)}`);


    } catch (e) {
        console.log(`    JNI test call failed:`, e.message);
    }
}

// 记录函数调用信息
function logFunctionCall(funcName, args, tid) {
    // 只记录部分重要函数的调用，避免刷屏
    console.log(`\n[Thread ${tid}] ${funcName} called`);

}

// 获取当前线程的JNIEnv
function getJNIEnvForCurrentThread() {
    var tid = Process.getCurrentThreadId();
    var data = g_jniEnvs.get(tid);

    if (!data) {
        console.log(`[-] No JNIEnv captured for thread ${tid} yet`);
        return null;
    }

    console.log(`[+] Using JNIEnv for thread ${tid}:`, data.env);
    return data.env;
}

// 获取所有捕获的JNIEnv
function getAllJNIEnvs() {
    console.log(`\n[+] Captured JNIEnvs for ${g_jniEnvs.size} threads:`);

    if (g_jniEnvs.size === 0) {
        console.log("    No JNIEnv captured yet");
        return;
    }

    for (var [tid, data] of g_jniEnvs) {
        console.log(`    Thread ${tid}:`);
        console.log(`      JNIEnv: ${data.env}`);
        console.log(`      From: ${data.functionName}`);
        console.log(`      Time: ${new Date(data.timestamp).toLocaleTimeString()}`);
    }
}

// 获取所有Hook的JVM函数
function getAllJVMFunctions() {
    console.log(`\n[+] Hooked ${Object.keys(g_jvmFunctions).length} JVM functions:`);

    var sorted = Object.keys(g_jvmFunctions).sort();
    for (var name of sorted) {
        console.log(`    ${name}: ${g_jvmFunctions[name]}`);
    }
}

// 通过偏移获取JNI函数
function getJNIFunctionByOffset(env, offset) {
    if (!env) return null;

    try {
        var funcTable = env.readPointer();
        var funcPtr = funcTable.add(offset * Process.pointerSize).readPointer();
        var module = Process.findModuleByAddress(funcPtr);

        console.log(`[+] Function at offset ${offset}: ${funcPtr} (${module ? module.name : 'unknown'})`);
        return funcPtr;

    } catch (e) {
        console.log(`[-] Error: ${e.message}`);
        return null;
    }
}

// 创建JNI函数调用
function createJNIFunction(env, offset, retType, argTypes) {
    var funcPtr = getJNIFunctionByOffset(env, offset);
    if (!funcPtr) return null;

    try {
        return new NativeFunction(funcPtr, retType, argTypes);
    } catch (e) {
        console.log(`[-] Failed to create NativeFunction: ${e.message}`);
        return null;
    }
}

// 示例：使用JNIEnv调用FindClass
function callJNIFindClass(env, className) {
    if (!env) return null;

    try {
        // FindClass 通常在偏移6
        var FindClass = getJNIFunctionByOffset(env, 6);
        if (!FindClass) return null;

        var JNI_FindClass = new NativeFunction(FindClass, 'pointer', ['pointer', 'pointer']);

        // 分配并写入类名字符串
        var classNamePtr = Memory.allocUtf8String(className);

        // 调用
        var result = JNI_FindClass(env, classNamePtr);
        console.log(`[+] FindClass("${className}") returned:`, result);

        return result;

    } catch (e) {
        console.log(`[-] FindClass failed: ${e.message}`);
        return null;
    }
}

function hookJNIFunctions(){

    //todo

    console.log("[+] JNI Functions Hooked")
}