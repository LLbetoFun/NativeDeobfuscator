var g_jniEnvs = new Map();

// 保存JVM相关的关键函数地址
var g_jvmFunctions = {};

// 要Hook的所有JVM函数列表（合并了之前的所有函数）
var JVM_FUNCTIONS_TO_HOOK = [
    // 核心JVM函数
    "JVM_DefineClass",
    "JVM_DefineClassWithSource",
    "JVM_FindClass",
    "JVM_GetClassMethods",
    "JVM_RegisterNatives",
    "JVM_GetClassDeclaredMethods",
    "JVM_GetArrayElement",
    "JVM_GetArrayLength",
    "JVM_CurrentTimeMillis",
    // 其他常用JVM函数
    "JVM_AllocateNewArray",
    "JVM_AllocateNewObject",
    "JVM_GetClassCPEntriesCount",
    "JVM_GetClassFieldsCount",
    "JVM_GetClassMethodsCount",
    "JVM_GetClassVersion",
    "JVM_GetClassName",
    "JVM_GetClassSignature",
    "JVM_IsInterface",
    "JVM_IsPrimitiveClass",
    "JVM_GetClassLoader",
    "JVM_GetProtectionDomain",
    "JVM_FreeMemory"
];

// 需要Hook但可能不直接是JVM_前缀的函数
var EXTRA_PATTERNS = [
    "DefineClass",
    "FindClass",
    "RegisterNatives",
    "GetClassMethods"
];

var testLogs = false;

var jniFuncTable = {

    // JNI函数偏移表（基于JNINativeInterface_结构体定义）
    offsets: {
        // 保留字段 (0-3)
        reserved0: 0 * Process.pointerSize,
        reserved1: 1 * Process.pointerSize,
        reserved2: 2 * Process.pointerSize,
        reserved3: 3 * Process.pointerSize,

        // 版本相关 (4)
        GetVersion: 4 * Process.pointerSize,

        // 类操作 (5-6)
        DefineClass: 5 * Process.pointerSize,
        FindClass: 6 * Process.pointerSize,

        // 反射相关 (7-9)
        FromReflectedMethod: 7 * Process.pointerSize,
        FromReflectedField: 8 * Process.pointerSize,
        ToReflectedMethod: 9 * Process.pointerSize,

        // 类操作 (10-11)
        GetSuperclass: 10 * Process.pointerSize,
        IsAssignableFrom: 11 * Process.pointerSize,

        // 反射相关 (12)
        ToReflectedField: 12 * Process.pointerSize,

        // 异常处理 (13-18)
        Throw: 13 * Process.pointerSize,
        ThrowNew: 14 * Process.pointerSize,
        ExceptionOccurred: 15 * Process.pointerSize,
        ExceptionDescribe: 16 * Process.pointerSize,
        ExceptionClear: 17 * Process.pointerSize,
        FatalError: 18 * Process.pointerSize,

        // 引用管理 (19-26)
        PushLocalFrame: 19 * Process.pointerSize,
        PopLocalFrame: 20 * Process.pointerSize,
        NewGlobalRef: 21 * Process.pointerSize,
        DeleteGlobalRef: 22 * Process.pointerSize,
        DeleteLocalRef: 23 * Process.pointerSize,
        IsSameObject: 24 * Process.pointerSize,
        NewLocalRef: 25 * Process.pointerSize,
        EnsureLocalCapacity: 26 * Process.pointerSize,

        // 对象创建 (27-31)
        AllocObject: 27 * Process.pointerSize,
        NewObject: 28 * Process.pointerSize,      // 注意：NewObject 在 AllocObject 之后
        NewObjectV: 29 * Process.pointerSize,
        NewObjectA: 30 * Process.pointerSize,

        // 类操作 (31-32)
        GetObjectClass: 31 * Process.pointerSize,
        IsInstanceOf: 32 * Process.pointerSize,

        // Method ID (33)
        GetMethodID: 33 * Process.pointerSize,

        // 实例方法调用 (34-69)
        CallObjectMethod: 34 * Process.pointerSize,
        CallObjectMethodV: 35 * Process.pointerSize,
        CallObjectMethodA: 36 * Process.pointerSize,
        CallBooleanMethod: 37 * Process.pointerSize,
        CallBooleanMethodV: 38 * Process.pointerSize,
        CallBooleanMethodA: 39 * Process.pointerSize,
        CallByteMethod: 40 * Process.pointerSize,
        CallByteMethodV: 41 * Process.pointerSize,
        CallByteMethodA: 42 * Process.pointerSize,
        CallCharMethod: 43 * Process.pointerSize,
        CallCharMethodV: 44 * Process.pointerSize,
        CallCharMethodA: 45 * Process.pointerSize,
        CallShortMethod: 46 * Process.pointerSize,
        CallShortMethodV: 47 * Process.pointerSize,
        CallShortMethodA: 48 * Process.pointerSize,
        CallIntMethod: 49 * Process.pointerSize,
        CallIntMethodV: 50 * Process.pointerSize,
        CallIntMethodA: 51 * Process.pointerSize,
        CallLongMethod: 52 * Process.pointerSize,
        CallLongMethodV: 53 * Process.pointerSize,
        CallLongMethodA: 54 * Process.pointerSize,
        CallFloatMethod: 55 * Process.pointerSize,
        CallFloatMethodV: 56 * Process.pointerSize,
        CallFloatMethodA: 57 * Process.pointerSize,
        CallDoubleMethod: 58 * Process.pointerSize,
        CallDoubleMethodV: 59 * Process.pointerSize,
        CallDoubleMethodA: 60 * Process.pointerSize,
        CallVoidMethod: 61 * Process.pointerSize,
        CallVoidMethodV: 62 * Process.pointerSize,
        CallVoidMethodA: 63 * Process.pointerSize,

        // 非虚方法调用 (64-99)
        CallNonvirtualObjectMethod: 64 * Process.pointerSize,
        CallNonvirtualObjectMethodV: 65 * Process.pointerSize,
        CallNonvirtualObjectMethodA: 66 * Process.pointerSize,
        CallNonvirtualBooleanMethod: 67 * Process.pointerSize,
        CallNonvirtualBooleanMethodV: 68 * Process.pointerSize,
        CallNonvirtualBooleanMethodA: 69 * Process.pointerSize,
        CallNonvirtualByteMethod: 70 * Process.pointerSize,
        CallNonvirtualByteMethodV: 71 * Process.pointerSize,
        CallNonvirtualByteMethodA: 72 * Process.pointerSize,
        CallNonvirtualCharMethod: 73 * Process.pointerSize,
        CallNonvirtualCharMethodV: 74 * Process.pointerSize,
        CallNonvirtualCharMethodA: 75 * Process.pointerSize,
        CallNonvirtualShortMethod: 76 * Process.pointerSize,
        CallNonvirtualShortMethodV: 77 * Process.pointerSize,
        CallNonvirtualShortMethodA: 78 * Process.pointerSize,
        CallNonvirtualIntMethod: 79 * Process.pointerSize,
        CallNonvirtualIntMethodV: 80 * Process.pointerSize,
        CallNonvirtualIntMethodA: 81 * Process.pointerSize,
        CallNonvirtualLongMethod: 82 * Process.pointerSize,
        CallNonvirtualLongMethodV: 83 * Process.pointerSize,
        CallNonvirtualLongMethodA: 84 * Process.pointerSize,
        CallNonvirtualFloatMethod: 85 * Process.pointerSize,
        CallNonvirtualFloatMethodV: 86 * Process.pointerSize,
        CallNonvirtualFloatMethodA: 87 * Process.pointerSize,
        CallNonvirtualDoubleMethod: 88 * Process.pointerSize,
        CallNonvirtualDoubleMethodV: 89 * Process.pointerSize,
        CallNonvirtualDoubleMethodA: 90 * Process.pointerSize,
        CallNonvirtualVoidMethod: 91 * Process.pointerSize,
        CallNonvirtualVoidMethodV: 92 * Process.pointerSize,
        CallNonvirtualVoidMethodA: 93 * Process.pointerSize,

        // Field ID (94)
        GetFieldID: 94 * Process.pointerSize,

        // 实例字段访问 (95-113)
        GetObjectField: 95 * Process.pointerSize,
        GetBooleanField: 96 * Process.pointerSize,
        GetByteField: 97 * Process.pointerSize,
        GetCharField: 98 * Process.pointerSize,
        GetShortField: 99 * Process.pointerSize,
        GetIntField: 100 * Process.pointerSize,
        GetLongField: 101 * Process.pointerSize,
        GetFloatField: 102 * Process.pointerSize,
        GetDoubleField: 103 * Process.pointerSize,
        SetObjectField: 104 * Process.pointerSize,
        SetBooleanField: 105 * Process.pointerSize,
        SetByteField: 106 * Process.pointerSize,
        SetCharField: 107 * Process.pointerSize,
        SetShortField: 108 * Process.pointerSize,
        SetIntField: 109 * Process.pointerSize,
        SetLongField: 110 * Process.pointerSize,
        SetFloatField: 111 * Process.pointerSize,
        SetDoubleField: 112 * Process.pointerSize,

        // 静态方法ID (113)
        GetStaticMethodID: 113 * Process.pointerSize,

        // 静态方法调用 (114-149)
        CallStaticObjectMethod: 114 * Process.pointerSize,
        CallStaticObjectMethodV: 115 * Process.pointerSize,
        CallStaticObjectMethodA: 116 * Process.pointerSize,
        CallStaticBooleanMethod: 117 * Process.pointerSize,
        CallStaticBooleanMethodV: 118 * Process.pointerSize,
        CallStaticBooleanMethodA: 119 * Process.pointerSize,
        CallStaticByteMethod: 120 * Process.pointerSize,
        CallStaticByteMethodV: 121 * Process.pointerSize,
        CallStaticByteMethodA: 122 * Process.pointerSize,
        CallStaticCharMethod: 123 * Process.pointerSize,
        CallStaticCharMethodV: 124 * Process.pointerSize,
        CallStaticCharMethodA: 125 * Process.pointerSize,
        CallStaticShortMethod: 126 * Process.pointerSize,
        CallStaticShortMethodV: 127 * Process.pointerSize,
        CallStaticShortMethodA: 128 * Process.pointerSize,
        CallStaticIntMethod: 129 * Process.pointerSize,
        CallStaticIntMethodV: 130 * Process.pointerSize,
        CallStaticIntMethodA: 131 * Process.pointerSize,
        CallStaticLongMethod: 132 * Process.pointerSize,
        CallStaticLongMethodV: 133 * Process.pointerSize,
        CallStaticLongMethodA: 134 * Process.pointerSize,
        CallStaticFloatMethod: 135 * Process.pointerSize,
        CallStaticFloatMethodV: 136 * Process.pointerSize,
        CallStaticFloatMethodA: 137 * Process.pointerSize,
        CallStaticDoubleMethod: 138 * Process.pointerSize,
        CallStaticDoubleMethodV: 139 * Process.pointerSize,
        CallStaticDoubleMethodA: 140 * Process.pointerSize,
        CallStaticVoidMethod: 141 * Process.pointerSize,
        CallStaticVoidMethodV: 142 * Process.pointerSize,
        CallStaticVoidMethodA: 143 * Process.pointerSize,

        // 静态字段ID (144)
        GetStaticFieldID: 144 * Process.pointerSize,

        // 静态字段访问 (145-163)
        GetStaticObjectField: 145 * Process.pointerSize,
        GetStaticBooleanField: 146 * Process.pointerSize,
        GetStaticByteField: 147 * Process.pointerSize,
        GetStaticCharField: 148 * Process.pointerSize,
        GetStaticShortField: 149 * Process.pointerSize,
        GetStaticIntField: 150 * Process.pointerSize,
        GetStaticLongField: 151 * Process.pointerSize,
        GetStaticFloatField: 152 * Process.pointerSize,
        GetStaticDoubleField: 153 * Process.pointerSize,
        SetStaticObjectField: 154 * Process.pointerSize,
        SetStaticBooleanField: 155 * Process.pointerSize,
        SetStaticByteField: 156 * Process.pointerSize,
        SetStaticCharField: 157 * Process.pointerSize,
        SetStaticShortField: 158 * Process.pointerSize,
        SetStaticIntField: 159 * Process.pointerSize,
        SetStaticLongField: 160 * Process.pointerSize,
        SetStaticFloatField: 161 * Process.pointerSize,
        SetStaticDoubleField: 162 * Process.pointerSize,

        // 字符串操作 (Unicode) (163-166)
        NewString: 163 * Process.pointerSize,
        GetStringLength: 164 * Process.pointerSize,
        GetStringChars: 165 * Process.pointerSize,
        ReleaseStringChars: 166 * Process.pointerSize,

        // 字符串操作 (UTF-8) (167-170)
        NewStringUTF: 167 * Process.pointerSize,
        GetStringUTFLength: 168 * Process.pointerSize,
        GetStringUTFChars: 169 * Process.pointerSize,
        ReleaseStringUTFChars: 170 * Process.pointerSize,

        // 数组操作 (171)
        GetArrayLength: 171 * Process.pointerSize,

        // 对象数组操作 (172-174)
        NewObjectArray: 172 * Process.pointerSize,
        GetObjectArrayElement: 173 * Process.pointerSize,
        SetObjectArrayElement: 174 * Process.pointerSize,

        // 基本类型数组创建 (175-182)
        NewBooleanArray: 175 * Process.pointerSize,
        NewByteArray: 176 * Process.pointerSize,
        NewCharArray: 177 * Process.pointerSize,
        NewShortArray: 178 * Process.pointerSize,
        NewIntArray: 179 * Process.pointerSize,
        NewLongArray: 180 * Process.pointerSize,
        NewFloatArray: 181 * Process.pointerSize,
        NewDoubleArray: 182 * Process.pointerSize,

        // 基本类型数组元素获取 (183-190)
        GetBooleanArrayElements: 183 * Process.pointerSize,
        GetByteArrayElements: 184 * Process.pointerSize,
        GetCharArrayElements: 185 * Process.pointerSize,
        GetShortArrayElements: 186 * Process.pointerSize,
        GetIntArrayElements: 187 * Process.pointerSize,
        GetLongArrayElements: 188 * Process.pointerSize,
        GetFloatArrayElements: 189 * Process.pointerSize,
        GetDoubleArrayElements: 190 * Process.pointerSize,

        // 基本类型数组元素释放 (191-198)
        ReleaseBooleanArrayElements: 191 * Process.pointerSize,
        ReleaseByteArrayElements: 192 * Process.pointerSize,
        ReleaseCharArrayElements: 193 * Process.pointerSize,
        ReleaseShortArrayElements: 194 * Process.pointerSize,
        ReleaseIntArrayElements: 195 * Process.pointerSize,
        ReleaseLongArrayElements: 196 * Process.pointerSize,
        ReleaseFloatArrayElements: 197 * Process.pointerSize,
        ReleaseDoubleArrayElements: 198 * Process.pointerSize,

        // 基本类型数组区域获取 (199-206)
        GetBooleanArrayRegion: 199 * Process.pointerSize,
        GetByteArrayRegion: 200 * Process.pointerSize,
        GetCharArrayRegion: 201 * Process.pointerSize,
        GetShortArrayRegion: 202 * Process.pointerSize,
        GetIntArrayRegion: 203 * Process.pointerSize,
        GetLongArrayRegion: 204 * Process.pointerSize,
        GetFloatArrayRegion: 205 * Process.pointerSize,
        GetDoubleArrayRegion: 206 * Process.pointerSize,

        // 基本类型数组区域设置 (207-214)
        SetBooleanArrayRegion: 207 * Process.pointerSize,
        SetByteArrayRegion: 208 * Process.pointerSize,
        SetCharArrayRegion: 209 * Process.pointerSize,
        SetShortArrayRegion: 210 * Process.pointerSize,
        SetIntArrayRegion: 211 * Process.pointerSize,
        SetLongArrayRegion: 212 * Process.pointerSize,
        SetFloatArrayRegion: 213 * Process.pointerSize,
        SetDoubleArrayRegion: 214 * Process.pointerSize,

        // 注册/注销Native方法 (215-216)
        RegisterNatives: 215 * Process.pointerSize,
        UnregisterNatives: 216 * Process.pointerSize,

        // Monitor (217-218)
        MonitorEnter: 217 * Process.pointerSize,
        MonitorExit: 218 * Process.pointerSize,

        // JavaVM (219)
        GetJavaVM: 219 * Process.pointerSize,

        // 字符串区域操作 (220-221)
        GetStringRegion: 220 * Process.pointerSize,
        GetStringUTFRegion: 221 * Process.pointerSize,

        // 临界区数组操作 (222-223)
        GetPrimitiveArrayCritical: 222 * Process.pointerSize,
        ReleasePrimitiveArrayCritical: 223 * Process.pointerSize,

        // 临界区字符串操作 (224-225)
        GetStringCritical: 224 * Process.pointerSize,
        ReleaseStringCritical: 225 * Process.pointerSize,

        // 弱引用 (226-227)
        NewWeakGlobalRef: 226 * Process.pointerSize,
        DeleteWeakGlobalRef: 227 * Process.pointerSize,

        // 异常检查 (228)
        ExceptionCheck: 228 * Process.pointerSize,

        // 直接缓冲区 (229-231)
        NewDirectByteBuffer: 229 * Process.pointerSize,
        GetDirectBufferAddress: 230 * Process.pointerSize,
        GetDirectBufferCapacity: 231 * Process.pointerSize,

        // JNI 1.6 特性 (232)
        GetObjectRefType: 232 * Process.pointerSize
    },

    // 函数签名映射 - 基于JNI类型定义
    signatures: {
        // 版本相关
        GetVersion: ['int', ['pointer']],
        DefineClass: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'int', 'pointer']],
        FindClass: ['pointer', ['pointer', 'pointer']],

        // 反射相关
        FromReflectedMethod: ['pointer', ['pointer', 'pointer']],
        FromReflectedField: ['pointer', ['pointer', 'pointer']],
        ToReflectedMethod: ['pointer', ['pointer', 'pointer', 'pointer', 'int']],

        // 类操作
        GetSuperclass: ['pointer', ['pointer', 'pointer']],
        IsAssignableFrom: ['int', ['pointer', 'pointer', 'pointer']],

        // 异常处理
        Throw: ['int', ['pointer', 'pointer']],
        ThrowNew: ['int', ['pointer', 'pointer', 'pointer']],
        ExceptionOccurred: ['pointer', ['pointer']],
        ExceptionDescribe: ['void', ['pointer']],
        ExceptionClear: ['void', ['pointer']],
        FatalError: ['void', ['pointer', 'pointer']],
        ExceptionCheck: ['int', ['pointer']],

        // 引用管理
        PushLocalFrame: ['int', ['pointer', 'int']],
        PopLocalFrame: ['pointer', ['pointer', 'pointer']],
        NewGlobalRef: ['pointer', ['pointer', 'pointer']],
        DeleteGlobalRef: ['void', ['pointer', 'pointer']],
        DeleteLocalRef: ['void', ['pointer', 'pointer']],
        IsSameObject: ['int', ['pointer', 'pointer', 'pointer']],
        NewLocalRef: ['pointer', ['pointer', 'pointer']],
        EnsureLocalCapacity: ['int', ['pointer', 'int']],
        NewWeakGlobalRef: ['pointer', ['pointer', 'pointer']],
        DeleteWeakGlobalRef: ['void', ['pointer', 'pointer']],

        // Method/Field ID
        GetMethodID: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        GetStaticMethodID: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        GetFieldID: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        GetStaticFieldID: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],

        // String操作 (UTF-8)
        NewStringUTF: ['pointer', ['pointer', 'pointer']],
        GetStringUTFLength: ['int', ['pointer', 'pointer']],
        GetStringUTFChars: ['pointer', ['pointer', 'pointer', 'pointer']],
        ReleaseStringUTFChars: ['void', ['pointer', 'pointer', 'pointer']],

        // 数组操作
        GetArrayLength: ['int', ['pointer', 'pointer']],
        NewObjectArray: ['pointer', ['pointer', 'int', 'pointer', 'pointer']],
        GetObjectArrayElement: ['pointer', ['pointer', 'pointer', 'int']],
        SetObjectArrayElement: ['void', ['pointer', 'pointer', 'int', 'pointer']],

        // 基本类型数组创建
        NewBooleanArray: ['pointer', ['pointer', 'int']],
        NewByteArray: ['pointer', ['pointer', 'int']],
        NewCharArray: ['pointer', ['pointer', 'int']],
        NewShortArray: ['pointer', ['pointer', 'int']],
        NewIntArray: ['pointer', ['pointer', 'int']],
        NewLongArray: ['pointer', ['pointer', 'int']],
        NewFloatArray: ['pointer', ['pointer', 'int']],
        NewDoubleArray: ['pointer', ['pointer', 'int']],

        // 基本类型数组元素获取
        GetBooleanArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetByteArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetCharArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetShortArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetIntArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetLongArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetFloatArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetDoubleArrayElements: ['pointer', ['pointer', 'pointer', 'pointer']],

        // 基本类型数组元素释放
        ReleaseBooleanArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseByteArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseCharArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseShortArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseIntArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseLongArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseFloatArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        ReleaseDoubleArrayElements: ['void', ['pointer', 'pointer', 'pointer', 'int']],

        // 基本类型数组区域操作
        GetBooleanArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetByteArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetCharArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetShortArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetIntArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetLongArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetFloatArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetDoubleArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetBooleanArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetByteArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetCharArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetShortArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetIntArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetLongArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetFloatArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        SetDoubleArrayRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],

        // 对象操作
        AllocObject: ['pointer', ['pointer', 'pointer']],
        NewObjectV: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        NewObjectA: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        NewObject: ['pointer', ['pointer', 'pointer', 'pointer']],
        GetObjectClass: ['pointer', ['pointer', 'pointer']],
        IsInstanceOf: ['int', ['pointer', 'pointer', 'pointer']],

        // 方法调用 (实例方法)
        CallObjectMethod: ['pointer', ['pointer', 'pointer', 'pointer']],
        CallObjectMethodV: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallObjectMethodA: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallBooleanMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallBooleanMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallBooleanMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallByteMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallByteMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallByteMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallCharMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallCharMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallCharMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallShortMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallShortMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallShortMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallIntMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallIntMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallIntMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallLongMethod: ['int64', ['pointer', 'pointer', 'pointer']],
        CallLongMethodV: ['int64', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallLongMethodA: ['int64', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallFloatMethod: ['float', ['pointer', 'pointer', 'pointer']],
        CallFloatMethodV: ['float', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallFloatMethodA: ['float', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallDoubleMethod: ['double', ['pointer', 'pointer', 'pointer']],
        CallDoubleMethodV: ['double', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallDoubleMethodA: ['double', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallVoidMethod: ['void', ['pointer', 'pointer', 'pointer']],
        CallVoidMethodV: ['void', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallVoidMethodA: ['void', ['pointer', 'pointer', 'pointer', 'pointer']],

        // 静态方法调用
        CallStaticObjectMethod: ['pointer', ['pointer', 'pointer', 'pointer']],
        CallStaticObjectMethodV: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticObjectMethodA: ['pointer', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticBooleanMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallStaticBooleanMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticBooleanMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticByteMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallStaticByteMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticByteMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticCharMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallStaticCharMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticCharMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticShortMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallStaticShortMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticShortMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticIntMethod: ['int', ['pointer', 'pointer', 'pointer']],
        CallStaticIntMethodV: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticIntMethodA: ['int', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticLongMethod: ['int64', ['pointer', 'pointer', 'pointer']],
        CallStaticLongMethodV: ['int64', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticLongMethodA: ['int64', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticFloatMethod: ['float', ['pointer', 'pointer', 'pointer']],
        CallStaticFloatMethodV: ['float', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticFloatMethodA: ['float', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticDoubleMethod: ['double', ['pointer', 'pointer', 'pointer']],
        CallStaticDoubleMethodV: ['double', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticDoubleMethodA: ['double', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticVoidMethod: ['void', ['pointer', 'pointer', 'pointer']],
        CallStaticVoidMethodV: ['void', ['pointer', 'pointer', 'pointer', 'pointer']],
        CallStaticVoidMethodA: ['void', ['pointer', 'pointer', 'pointer', 'pointer']],

        // 字段访问 (实例字段)
        GetBooleanField: ['int', ['pointer', 'pointer', 'pointer']],
        GetByteField: ['int', ['pointer', 'pointer', 'pointer']],
        GetCharField: ['int', ['pointer', 'pointer', 'pointer']],
        GetShortField: ['int', ['pointer', 'pointer', 'pointer']],
        GetIntField: ['int', ['pointer', 'pointer', 'pointer']],
        GetLongField: ['int64', ['pointer', 'pointer', 'pointer']],
        GetFloatField: ['float', ['pointer', 'pointer', 'pointer']],
        GetDoubleField: ['double', ['pointer', 'pointer', 'pointer']],
        SetBooleanField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetByteField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetCharField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetShortField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetIntField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetLongField: ['void', ['pointer', 'pointer', 'pointer', 'int64']],
        SetFloatField: ['void', ['pointer', 'pointer', 'pointer', 'float']],
        SetDoubleField: ['void', ['pointer', 'pointer', 'pointer', 'double']],

        // 静态字段访问
        GetStaticBooleanField: ['int', ['pointer', 'pointer', 'pointer']],
        GetStaticByteField: ['int', ['pointer', 'pointer', 'pointer']],
        GetStaticCharField: ['int', ['pointer', 'pointer', 'pointer']],
        GetStaticShortField: ['int', ['pointer', 'pointer', 'pointer']],
        GetStaticIntField: ['int', ['pointer', 'pointer', 'pointer']],
        GetStaticLongField: ['int64', ['pointer', 'pointer', 'pointer']],
        GetStaticFloatField: ['float', ['pointer', 'pointer', 'pointer']],
        GetStaticDoubleField: ['double', ['pointer', 'pointer', 'pointer']],
        SetStaticBooleanField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetStaticByteField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetStaticCharField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetStaticShortField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetStaticIntField: ['void', ['pointer', 'pointer', 'pointer', 'int']],
        SetStaticLongField: ['void', ['pointer', 'pointer', 'pointer', 'int64']],
        SetStaticFloatField: ['void', ['pointer', 'pointer', 'pointer', 'float']],
        SetStaticDoubleField: ['void', ['pointer', 'pointer', 'pointer', 'double']],

        // 字符串操作 (Unicode)
        NewString: ['pointer', ['pointer', 'pointer', 'int']],
        GetStringLength: ['int', ['pointer', 'pointer']],
        GetStringChars: ['pointer', ['pointer', 'pointer', 'pointer']],
        ReleaseStringChars: ['void', ['pointer', 'pointer', 'pointer']],
        GetStringRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetStringUTFRegion: ['void', ['pointer', 'pointer', 'int', 'int', 'pointer']],
        GetStringCritical: ['pointer', ['pointer', 'pointer', 'pointer']],
        ReleaseStringCritical: ['void', ['pointer', 'pointer', 'pointer']],

        // 数组操作 (补充)
        GetPrimitiveArrayCritical: ['pointer', ['pointer', 'pointer', 'pointer']],
        ReleasePrimitiveArrayCritical: ['void', ['pointer', 'pointer', 'pointer', 'int']],

        // Monitor
        MonitorEnter: ['int', ['pointer', 'pointer']],
        MonitorExit: ['int', ['pointer', 'pointer']],

        // 直接缓冲区
        NewDirectByteBuffer: ['pointer', ['pointer', 'pointer', 'int64']],
        GetDirectBufferAddress: ['pointer', ['pointer', 'pointer']],
        GetDirectBufferCapacity: ['int64', ['pointer', 'pointer']],

        // 引用类型
        GetObjectRefType: ['int', ['pointer', 'pointer']]
    },

    // 获取函数名的辅助方法
    getFunctionName: function(offset) {
        for (var name in this.offsets) {
            if (this.offsets[name] === offset) {
                return name;
            }
        }
        return null;
    },

    // 获取函数信息
    getFunctionAt: function(env, offset) {
        if (!env || env.isNull()) return null;

        try {
            var funcTable = env.readPointer();
            if (!funcTable || funcTable.isNull()) return null;

            var funcPtr = funcTable.add(offset).readPointer();

            if (funcPtr && !funcPtr.isNull()) {
                var funcName = this.getFunctionName(offset);
                var signature = this.signatures[funcName];

                if (signature) {
                    return {
                        offset: offset,
                        ptr: funcPtr,
                        name: funcName,
                        signature: signature,
                        nativeFunction: new NativeFunction(funcPtr, signature[0], signature[1])
                    };
                }
            }
        } catch (e) {
            console.log(`[-] Error at offset ${offset}: ${e.message}`);
        }
        return null;
    }
};

function waitUntil(conditionFn, callback, interval = 100, timeout = 0) {
    const startTime = Date.now();

    const check = () => {
        // 检查是否超时
        if (timeout > 0 && Date.now() - startTime > timeout) {
            console.log(`[-] 等待超时 (${timeout}ms)`);
            callback(null, new Error('等待超时'));
            return;
        }

        // 检查条件
        try {
            if (conditionFn()) {
                callback(true);
                return;
            }
        } catch (e) {
            callback(null, e);
            return;
        }

        // 继续等待
        setTimeout(check, interval);
    };

    check();
}


