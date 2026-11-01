# 布吉岛（HeyPixel）反注入拆解

> 闲的。把 94 MB 的客户端 mod 拆了。
> 拆完的感觉：**这玩意儿看着像那么回事，实际上不干 B 事。**

拆的是 `mods\heypixel`，94.76 MB。旁边那个 `observer_system`（0.12 MB）名字起得像监控中心，点开一看是附近玩家列表加目标背包，PvP 辅助。跟反作弊没关系，顺带说一声免得有人跟我一样被骗。

---

## 先看体积

```
94.76 MB
├─ assets/       ~90 MB   贴图模型字体音效
├─ com/heypixel/  ~4 MB   代码
└─ lib/           26 MB   MaxHook.x64.dll + 两个 MinHook
```

混淆看着牛逼，实际上代码加起来还没那个 DLL 大。

```
lib/MaxHook.x64.dll    26,666,344 bytes
lib/MinHook.x64.dll        15,360 bytes
lib/MinHook.x86.dll        ~15,000 bytes
```

MinHook 原版编译出来就是 15 KB 上下，一个是 64 位一个是 32 位 —— 一个 Java 进程里放个 32 位的 dll，是打算在什么场景下用？

---

## Java 层：实际上不干 B 事

类名长这样：

```
com/heypixel/😸😺😿😺😺😼😺😽😼😻😸😼😿😿😿🙀😼😾😻🙀😽😻😽😻😾😼😹😿😹😸😿😿🙀😸😽.class
com/heypixel/iiiIIIiiIIiiIIiiIiiiiIIiiIiIiiiiiIIiIIIIiIIiiIiiiiIIiiIiIiii.class
```

emoji 当类名，32 个字符一组。这是 ProGuard 那类工具换个字典就能生成的东西，不是"自研混淆"。

而且生成了也没用。`javap -c` 一开，方法体、字符串常量、字段引用全在那儿摆着，`strings` 一下能捞出一堆中文提示。

**没有字符串加密，没有控制流平坦化，没有反射调用改写。** 就是把类名换成了表情包，然后大概觉得这样就没人看得懂了。


对比 Zelix 那种混淆 —— 字符串全加密、控制流打散成状态机、插花指令、加水印防二次分发 —— 这个连门槛都没摸到，属于在门口做了个闪身步就回去交差了。

然后把 11,942 个条目全扫了一遍，关键词是：

```
java/lang/instrument  agentmain  premain  VirtualMachine
sun.tools.attach      jdk.attach  Instrumentation
JNI_GetCreatedJavaVMs  jvm.dll  Frida  MinHook
EnumProcessModules    IsDebuggerPresent
```

**结论**

检测了个滚木

Java agent 注入进来之后，痕迹在 Java 层全都在：`java.class.path` 里多一条、ClassLoader 里凭空多一批类、有个 `Instrumentation` 实例在内存里飘着、线程列表多几个没见过的。这些查起来都不难 —— 反射读一遍 `System.getProperty("java.class.path")` 就行，连 JVMTI 都不用。

**它一条都没查**


所以这 94 MB 里的 Java 代码，就是皮肤、家具、宠物、活动、UI，再挂一个 OBS 叠加层（包名 `com/heypixel/obsoverlay`，名字自己都写出来了）。

看门的东西全在原生层，而原生层我们下面再看。

---

## native层：26 MB 的 DLL，24 MB 是空气

节表摊开：

```
.text      vsize 0x005F8E76  raw 0x005F9000    ≈6 MB 代码
.detourc   0x00002230        ← MS Detours 常量段
.detourd   0x00000010        ← MS Detours 数据段
.fptable   0x00000100        ← 函数指针表
.tls       0x00010000        ← 第二个 .tls，重复
.bugland   vsize 0x01770000  raw 0x00000000   ← 24 MB 纯虚拟段
.boot      vsize 0x01090800  raw 0x01090800   ← 16.6 MB 内嵌载荷
.reloc     0x00010000        ← 第二个 .reloc，重复
```


**`.detourc` / `.detourd`** —— 这是微软 Detours 的特征段名，2011 年开源的库。所以这是个 inline hook 引擎。**是微软写的**

**两个 `.tls`、两个 `.reloc`** —— 正常链接器不会生成这种东西。要么是自定义链接脚本，要么是后处理工具过了一遍。反正不是原样编出来的。

**`.boot` 16.6 MB 全在文件里，`.bugland` 24 MB 文件里零字节** —— 前者是加密载荷，后者是运行时才提交的虚拟内存。

**前 512 KB 扫不到任何可读字符串** —— `VMProtect`、`detours`、`hook`、报错信息，一个都没有。

所以那个"26 MB 强力反作弊引擎"，拆开是：

```
6 MB 代码  +  16.6 MB 加密数据  +  24 MB 空气
```

24 MB 空气。

`VirtualSize` 写 `0x01770000`，`SizeOfRawData` 写 0 —— 文件里一个字节都不放，运行时再 `VirtualAlloc` 提交。
---

## 它查注入，就这几个角度

| 角度 | 手段 | 强度 |
|---|---|---|
| 模块 | `CreateToolhelp32Snapshot`，或直接走 PEB 的 `InLoadOrderModuleList`，找磁盘上没有对应文件的 | 中 |
| 注入 API | Detours 挂 `LoadLibraryW` / `CreateRemoteThread` / `VirtualAllocEx` / `WriteProcessMemory` | 中 |
| 内存签名 | `VirtualQueryEx` 遍历可执行页，找 `MZ` + `PE\0\0` | 低 |
| 内存属性 | 找 `MEM_PRIVATE` 且 `PAGE_EXECUTE_*` 的区域 | 中 |
| 线程 | 遍历线程，看 `StartAddress` 在不在已加载模块的地址段里 | 中 |
| JVM（存疑） | 拿到 `jvmtiEnv` 后调 `GetLoadedClasses` | 未知 |

前五条是任何一个写过注入检测的人第一天就会想到的东西，没啥新鲜的，网上一搜一大把。第六条要看那 16.6 MB 加密载荷里到底有没有塞 JVM 接口 —— 解不开，确认不了，但你应该假设它做了。

而这六条，全部是"你怎么进来的"。

至于你进来之后干了什么，那不管。

**没有一条跟"进来之后"有关。**

---

## 怎么绕

### 模块枚举 → 手动映射

别这么干：

```c
OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryW)
```

这串里每一步都可能是 hook 点，而且 `LoadLibrary` 加载完，模块直接进 PEB 链表，`CreateToolhelp32Snapshot` 一查就现形。

自己映射九个步骤：

```
读 dll → OpenProcess → VirtualAllocEx(SizeOfImage)
→ 逐节区铺 → 重定位 → 回填 IAT → RtlAddFunctionTable
→ 跑 TLS 回调 → DllMain
```

两个坑，踩过的都懂：

**重定位** —— `VirtualAllocEx` 给你的地址跟 `ImageBase` 不一样，所有绝对地址全错。不做重定位，代码跑起来就是野指针满天飞，然后你花三个小时以为是导出函数写错了。

**IAT 对账** —— 你在自己进程里 `GetProcAddress` 拿到的是本地地址，目标进程里同名模块通常同址（系统 DLL 会重定位到同一个位置），但**不是必然**。不一致就放弃，硬填进去一调就崩，崩在目标进程里，你连堆栈都看不到。

全程不碰 `LoadLibraryW`，模块也不进 PEB 链表。这是唯一能让模块枚举瞎掉的办法。

### PE 签名扫描 → 抹头

```c
VirtualProtectEx(hp, base, 0x1000, PAGE_READWRITE, &old);
WriteProcessMemory(hp, base, zeros, 0x1000, &written);
VirtualProtectEx(hp, base, 0x1000, old, &tmp);
```

抹 **0x1000 字节**，不是 64 字节。第一页里的是：

```
0x000  MZ 头
0x03C  e_lfanew
0x0xx  PE\0\0 + 文件头 + 可选头
0x1xx  数据目录（导入表、资源表、重定位表 RVA 全在这）
0x2xx  节表
```

抹 64 字节的那种做法，只能骗过"前两个字节是不是 `MZ`"这一种检查。写这种检测的人，大概率也就写了这么一行。

时机：**`DllMain` 返回之后**。在里面抹自己的头，加载器可能正在读这些数据，当场炸给你看，而且崩在加载器里，堆栈难看得一塌糊涂。

抹完的效果：内容扫描瞎了。但模块枚举依然看得到你 —— 这两件事是分开的，别指望抹头一并解决。

### 可执行私有内存 → module stomping

这条是抹头解决不了的。`VirtualQueryEx` 看到 `MEM_PRIVATE + PAGE_EXECUTE`，里面有没有 PE 头它不管，这块内存本身就不该存在。

思路：别自己开地，借别人的地。

```c
// 自己分配 → MEM_PRIVATE，一眼可疑
void *p = VirtualAllocEx(h, NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// 踩在已有镜像的空隙上 → MEM_IMAGE，看起来背后有文件
void *q = (void *)((BYTE *)winmmBase + offset_into_slack);
VirtualAllocEx(h, q, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
```

步骤：找一个用得不多的系统 DLL → 读节表找 `VirtualSize - SizeOfRawData` 够大的节 → 分配到节尾空隙 → 写 payload → 从那个地址执行。

代价：payload 不能太大、要重定位、别踩到那个 DLL 自己正在用的数据。做起来烦，但这是对付这条检测的唯一正路。

### 线程地址检查 → 线程劫持

`CreateRemoteThread` 起的线程，`StartAddress` 落在你自己分配的那块区域里 —— 不在任何模块的地址段内，扫一遍线程列表就看得出来。

```
SuspendThread → GetThreadContext（存 RIP/RSP）
→ 改 RIP 到入口 → ResumeThread → 跑完恢复 Context
```

这样 `StartAddress` 还是原来那个合法模块的地址。

坑：改 Context 很容易把线程栈搞崩。一定要有"跑完恢复"的兜底，不然目标进程直接给你表演一个闪退。

### 磁盘 / classpath 扫描 → 全内存

别往 `%TEMP%` 写 jar 再 attach。路径在 `%TEMP%` 里挂着、classpath 里多一条，两处都是痕迹，而且清理起来还麻烦。

JVMTI 直载：

```c
GetEnv(JVMTI_VERSION) → jvmtiEnv → AddCapabilities
→ DefineClass(引导类) → 从内存读 jar 字节 → 自定义 ClassLoader
```

磁盘上没有 jar，classpath 里没有条目。代价是要自己处理类加载顺序和资源查找，写到一半会想砸键盘。

### JVM 类枚举 → 只能改名

类进了 JVM，`GetLoadedClasses` 就能列出来，这条真没辙。

能做的只有改名字：包名别叫 `cheat`，类名短一点或者装得像原版（`RenderStateCache` 这种），线程名别叫 `mydll-loader`。

**这是降低可疑度，不是隐藏。** 别自我安慰说这样就找不到了。

---

## 自检

注入完自己先看一眼，别等着被踢了再回来翻日志：

```
[ ] 模块表里没有"磁盘上找不到"的条目
[ ] 头部前 8 字节不是 4D 5A
[ ] 没有 MEM_PRIVATE + PAGE_EXECUTE 的区域
[ ] 没有起始地址在模块外的线程
[ ] classpath 没多东西
[ ] %TEMP% 里没 jar / dll / log
```

前三项红了就别上线。

```powershell
param([Parameter(Mandatory=$true)][int]$TargetPid)

$p = Get-Process -Id $TargetPid

Write-Host "`n[1] 模块表（!! = 磁盘上找不到文件）" -ForegroundColor Cyan
$p.Modules | ForEach-Object {
    $flag = if ($_.FileName -and (Test-Path $_.FileName)) { "  " } else { "!!" }
    "{0} {1,-32} {2}" -f $flag, $_.ModuleName, $_.FileName
}

Write-Host "`n[2] 线程（start 落在所有模块区间外 = 可疑）" -ForegroundColor Cyan
Get-CimInstance Win32_Thread -Filter "ProcessHandle='$TargetPid'" -ErrorAction SilentlyContinue |
    Select-Object -First 20 | ForEach-Object {
        "  tid={0} start=0x{1:X}" -f $_.Handle, $_.StartAddress
    }
```

---

## 完整抹头代码

```c
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static BOOL find_module_base(DWORD pid, const wchar_t *name, BYTE **out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;

    MODULEENTRY32W me = {0};
    me.dwSize = sizeof(me);

    BOOL found = FALSE;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0) {
                *out = me.modBaseAddr;
                found = TRUE;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static BOOL wipe(DWORD pid, BYTE *base, DWORD bytes) {
    HANDLE hp = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                            FALSE, pid);
    if (!hp) return FALSE;

    DWORD old = 0;
    if (!VirtualProtectEx(hp, base, bytes, PAGE_READWRITE, &old)) {
        CloseHandle(hp);
        return FALSE;
    }

    BYTE *zeros = (BYTE *)calloc(1, bytes);
    SIZE_T written = 0;
    BOOL ok = WriteProcessMemory(hp, base, zeros, bytes, &written) && written == bytes;
    free(zeros);

    DWORD tmp = 0;
    VirtualProtectEx(hp, base, bytes, old, &tmp);
    CloseHandle(hp);
    return ok;
}

/* 抹完读回来确认，别信返回值 */
static void verify(DWORD pid, BYTE *base) {
    HANDLE hp = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (!hp) return;

    BYTE buf[16] = {0};
    SIZE_T got = 0;
    if (ReadProcessMemory(hp, base, buf, sizeof(buf), &got)) {
        printf("前 16 字节: ");
        for (SIZE_T i = 0; i < got; i++) printf("%02X ", buf[i]);
        printf("\n");
    }
    CloseHandle(hp);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        fwprintf(stderr, L"用法: wipe.exe <pid> <module.dll>\n");
        return 2;
    }

    DWORD pid = (DWORD)_wtoi(argv[1]);
    BYTE *base = NULL;
    if (!find_module_base(pid, argv[2], &base)) {
        fwprintf(stderr, L"没找到\n");
        return 1;
    }

    wprintf(L"基址 %p\n", (void *)base);
    if (!wipe(pid, base, 0x1000)) return 1;

    wprintf(L"抹完了\n");
    verify(pid, base);
    return 0;
}
```

```
gcc -O2 -o wipe.exe wipe.c
```

---

## 总结

问题：这东西到底防谁，结论是：防傻子。

它防的是那种从 GitHub 上复制一段 `CreateRemoteThread(LoadLibraryW)` 就敢往别人游戏里注入的人。防住了，很有成就感。

只要注入的人知道用手动映射，前面那一整套 —— Detours 挂 API、扫内存找 `MZ`、抹了 24 MB 空气的 `.bugland` —— 全部失效。六个检测点，五个能绕，剩下一个（JVM 类枚举）取决于那 16.6 MB 里到底写了什么，而我从头到尾没看到任何证据表明它真的调过 `GetLoadedClasses`。

**一个防注入模块，最大的检测面是模块枚举，而这个模块自己就是被 Java 加载器 `System.load` 进来的一个 dll。** 你们有没有想过，既然 dll 能进来，别人的 dll 就能进来，而你们唯一的应对是"看看有没有不认识的模块"？

再退一步说。就算你把所有注入都防住了，玩家手里的 Minecraft 是 Java 写的，`--add-opens`、`-javaagent`、`JAVA_TOOL_OPTIONS` 全在启动器手里攥着。真要动歪心思，谁还注入 dll 啊。

这套东西的定位，说白了就是**给不知道内情的人一种"我们做了防护"的观感**。好看，能用，拍宣传视频的时候很有说服力。

---

## 免责

拆着玩的笔记。抓包、逆向、读别人代码，都是正常研究。

**仅限学习与研究。** 拿去干别的

原生模块是加密的，凡是"它可能会……"都是推断，不是实锤。别当圣经。

---
## 致谢
本报告由DeepSeek V4.1 Flash协助完成

注：截至2026/11/01，经过两天的注入测试，均未出现任何封禁，黑屋的现象
