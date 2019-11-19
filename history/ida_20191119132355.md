# ida


跟IDA Pro有关的资源收集。当前包括的工具个数450左右，并根据功能进行了粗糙的分类。部分工具添加了中文描述。当前包括文章数金300个。


# 目录
- [工具](#f11ab1ff46aa300cc3e86528b8a98ad7)
    - [(92) 未分类](#c39a6d8598dde6abfeef43faf931beb5)
    - [结构体&&类的检测&&创建&&恢复](#fb4f0c061a72fc38656691746e7c45ce)
        - [(6) 未分类](#fa5ede9a4f58d4efd98585d3158be4fb)
        - [(8) C++类&&虚表](#4900b1626f10791748b20630af6d6123)
    - [(3) 收集](#a7dac37cd93b8bb42c7d6aedccb751b3)
    - [(9) 外观&&主题](#fabf03b862a776bbd8bcc4574943a65a)
    - [(4) 固件&&嵌入式设备](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e)
    - [签名(FLIRT等)&&比较(Diff)&&匹配](#02088f4884be6c9effb0f1e9a3795e58)
        - [(17) 未分类](#cf04b98ea9da0056c055e2050da980c1)
        - [FLIRT签名](#19360afa4287236abe47166154bc1ece)
            - [(3) FLIRT签名收集](#1c9d8dfef3c651480661f98418c49197)
            - [(2) FLIRT签名生成](#a9a63d23d32c6c789ca4d2e146c9b6d0)
        - [(11) Diff&&Match工具](#161e5a3437461dc8959cc923e6a18ef7)
        - [(7) Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a)
    - [(6) IDB操作](#5e91b280aab7f242cbc37d64ddbff82f)
    - [(5) 协作逆向&&多人操作相同IDB文件](#206ca17fc949b8e0ae62731d9bb244cb)
    - [(9) 与调试器同步&&通信&&交互](#f7d311685152ac005cfce5753c006e4b)
    - [导入导出&与其他工具交互](#6fb7e41786c49cc3811305c520dfe9a1)
        - [(13) 未分类](#8ad723b704b044e664970b11ce103c09)
        - [(5) Ghidra](#c7066b0c388cd447e980bf0eb38f39ab)
        - [(3) BinNavi](#11139e7d6db4c1cef22718868f29fe12)
        - [(3) BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a)
        - [(2) Radare2](#21ed198ae5a974877d7a635a4b039ae3)
        - [(3) Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd)
        - [(2) IntelPin](#dd0332da5a1482df414658250e6357f8)
    - [针对特定分析目标](#004c199e1dbf71769fbafcd8e58d1ead)
        - [(24) 未分类](#5578c56ca09a5804433524047840980e)
        - [(2) GoLang](#1b17ac638aaa09852966306760fda46b)
        - [(4) Windows驱动](#4c158ccc5aee04383755851844fdd137)
        - [(4) PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5)
        - [(32) Loader&Processor](#cb59d84840e41330a7b5e275c0b81725)
        - [(4) PDB](#f5e51763bb09d8fd47ee575a98bedca1)
        - [(2) Flash&&SWF](#7d0681efba2cf3adaba2780330cd923a)
        - [(4) 特定样本家族](#841d605300beba45c3be131988514a03)
        - [(1) CTF](#ad44205b2d943cfa2fa805b2643f4595)
    - [IDAPython本身](#ad68872e14f70db53e8d9519213ec039)
        - [(8) 未分类](#2299bc16945c25652e5ad4d48eae8eca)
        - [(1) cheatsheets](#c42137cf98d6042372b1fd43c3635135)
    - [(6) 指令参考&文档](#846eebe73bef533041d74fc711cafb43)
    - [辅助脚本编写](#c08ebe5b7eec9fc96f8eff36d1d5cc7d)
        - [(9) 未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2)
        - [(3) Qt](#1a56a5b726aaa55ec5b7a5087d6c8968)
        - [(3) 控制台&&窗口界面](#1721c09501e4defed9eaa78b8d708361)
        - [(2) 插件模板](#227fbff77e3a13569ef7b007344d5d2e)
        - [(2) 其他语言](#8b19bb8cf9a5bc9e6ab045f3b4fabf6a)
    - [(16) 古老的](#dc35a2b02780cdaa8effcae2b6ce623e)
    - [调试&&动态运行&动态数据](#e3e7030efc3b4de3b5b8750b7d93e6dd)
        - [(10) 未分类](#2944dda5289f494e5e636089db0d6a6a)
        - [(10) DBI数据](#0fbd352f703b507853c610a664f024d1)
        - [(4) 调试数据](#b31acf6c84a9506066d497af4e702bf5)
    - [(13) 反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9)
    - [(7) 反混淆](#7199e8787c0de5b428f50263f965fda7)
    - [效率&&导航&&快速访问&&图形&&图像&&可视化 ](#fcf75a0881617d1f684bc8b359c684d7)
        - [(15) 其他](#c5b120e1779b928d860ad64ff8d23264)
        - [(9) 显示增强](#03fac5b3abdbd56974894a261ce4e25f)
        - [(3) 图形&&图像](#3b1dba00630ce81cba525eea8fcdae08)
        - [(3) 搜索](#8f9468e9ab26128567f4be87ead108d7)
    - [(7) Android](#66052f824f5054aa0f70785a2389a478)
    - [Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O](#2adc0044b2703fb010b3bf73b1f1ea4a)
        - [(5) 未分类](#8530752bacfb388f3726555dc121cb1a)
        - [(3) 内核缓存](#82d0fa2d6934ce29794a651513934384)
        - [(3) Mach-O](#d249a8d09a3f25d75bb7ba8b32bd9ec5)
        - [(2) Swift](#1c698e298f6112a86c12881fbd8173c7)
    - [(9) ELF](#e5e403123c70ddae7bd904d3a3005dbb)
    - [(5) Microcode](#7a2977533ccdac70ee6e58a7853b756b)
    - [(6) 模拟器集成](#b38dab81610be087bd5bc7785269b8cc)
    - [新添加的](#c39dbae63d6a3302c4df8073b4d1cdc8)
    - [(4) 作为辅助&&构成其他的一环](#83de90385d03ac8ef27360bfcdc1ab48)
    - [漏洞](#1ded622dca60b67288a591351de16f8b)
        - [(7) 未分类](#385d6777d0747e79cccab0a19fa90e7e)
        - [(2) ROP](#cf2efa7e3edb24975b92d2e26ca825d2)
    - [(7) 补丁&&Patch](#7d557bc3d677d206ef6c5a35ca8b3a14)
    - [(3) 其他](#7dfd8abad50c14cd6bdc8d8b79b6f595)
    - [函数相关](#90bf5d31a3897400ac07e15545d4be02)
        - [(4) 未分类](#347a2158bdd92b00cd3d4ba9a0be00ae)
        - [(6) 重命名&&前缀&&标记](#73813456eeb8212fd45e0ea347bec349)
        - [(5) 导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc)
        - [(2) demangle](#cadae88b91a57345d266c68383eb05c5)
    - [(3) 污点分析&&符号执行](#34ac84853604a7741c61670f2a075d20)
    - [(8) 字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24)
    - [(3) 加密解密](#06d2caabef97cf663bd29af2b1fe270c)
- [文章](#18c6a45392d6b383ea24b363d2f3e76b)
    - [(146) 未分类](#4187e477ebc45d1721f045da62dbf4e8)
    - [(9) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
    - [(15) 恶意代码分析](#0b3e1936ad7c4ccc10642e994c653159)
    - [(6) 系列文章-Labeless插件介绍](#04cba8dbb72e95d9c721fe16a3b48783)
    - [(24) 系列文章-使用IDA从零开始学逆向](#1a2e56040cfc42c11c5b4fa86978cc19)
    - [系列文章-IDAPython-让你的生活更美好](#e838a1ecdcf3d068547dd0d7b5c446c6)
        - [(6) 原文](#7163f7c92c9443e17f3f76cc16c2d796)
        - [(5) 译文](#fc62c644a450f3e977af313edd5ab124)
    - [(5) 系列文章-使用IDA逆向C代码](#8433dd5df40aaf302b179b1fda1d2863)
    - [(50) 工具&&插件&&脚本介绍](#3d3bc775abd7f254ff9ff90d669017c9)
    - [(5) 翻译-TheIDAProBook](#ea11818602eb33e8b165eb18d3710965)
    - [(2) 翻译-ReverseEngineeringCodeWithIDAPro](#ec5f7b9ed06500c537aa25851a3f2d3a)
    - [(7) 逆向实战](#d8e48eb05d72db3ac1e050d8ebc546e1)
- [TODO](#35f8efcff18d0449029e9d3157ac0899)


# <a id="f11ab1ff46aa300cc3e86528b8a98ad7"></a>工具


- 以Github开源工具为主


***


## <a id="c39a6d8598dde6abfeef43faf931beb5"></a>未分类


- [**1037**星][2m] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) 多工具
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) 自动恢复手动构造的字符串
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) 
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) This plugin allows you to specify or choose a function type for indirect calls as described here: [Flare-Ida-Pro-Script](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) 识别函数使用的静态参数
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) FLIRT签名生成
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) 在目标Mach-O可执行文件的与Objective-C运行时相关的部分中定义的选择器引用及其实现之间创建交叉引用
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) 从XML文件中提取MSDN信息，添加到IDB数据库中
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) 使用代码模拟执行（flare-emu）, 恢复构造的字符串
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) 生成Hash数据库
- [**732**星][6m] [Py] [devttys0/ida](https://github.com/devttys0/ida) 多工具
    - [wpsearch](https://github.com/devttys0/ida/blob/master/scripts/wpsearch.py) 查找在MIPS WPS checksum实现中常见的立即数
    - [md5hash](https://github.com/devttys0/ida/tree/master/modules/md5hash) 纯Python版的MD5 hash实现（IDA的hashlib有问题）
    - [alleycat](https://github.com/devttys0/ida/tree/master/plugins/alleycat) 查找向指定的函数内代码块的路径、查找两个或多个函数之间的路径、生成交互式调用图、可编程
    - [codatify](https://github.com/devttys0/ida/tree/master/plugins/codatify) 定义IDA自动化分析时miss的ASCII字符串、函数、代码。将data段的所有未定义字节转换为DWORD（于是IDA可识别函数和跳转表指针）
    - [fluorescence](https://github.com/devttys0/ida/tree/master/plugins/fluorescence) 高亮函数调用指令
    - [leafblower](https://github.com/devttys0/ida/tree/master/plugins/leafblower) 识别常用的POSIX函数：printf, sprintf, memcmp, strcpy等
    - [localxrefs](https://github.com/devttys0/ida/tree/master/plugins/localxrefs) 在当前函数内部查找所有对任意选择文本的引用
    - [mipslocalvars](https://github.com/devttys0/ida/tree/master/plugins/mipslocalvars) 对栈上只用于存储寄存器的变量进行命名，简化栈数据分析（MISP）
    - [mipsrop](https://github.com/devttys0/ida/tree/master/plugins/mipsrop) 在MIPS可执行代码中搜寻ROP。查找常见的ROP
    - [rizzo](https://github.com/devttys0/ida/tree/master/plugins/rizzo) 对2个或多个IDB之间的函数进行识别和重命名，基于：函数签名、对唯一字符串/常量的引用、模糊签名、调用图
- [**308**星][27d] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) 软件补丁分析工具
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**272**星][3m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) 多脚本（还有的没列出在子工具）
    - [apt17scan.py](https://github.com/jpcertcc/aa-tools/blob/master/apt17scan.py) Volatility插件, 检测APT17相关的恶意代码并提取配置
    - [emdivi_postdata_decoder](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_postdata_decoder.py) 解码Emdivi post的数据
    - [emdivi_string_decryptor](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_string_decryptor.py) IDAPython脚本, 解密Emdivi内的字符串
- [**114**星][1y] [Py] [vallejocc/reverse-engineering-arsenal](https://github.com/vallejocc/Reverse-Engineering-Arsenal) 逆向脚本收集
    - [WinDbg](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/WinDbg) Windbg脚本收集
    - [IDA-set_symbols_for_addresses](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/set_symbols_for_addresses.py) 遍历所有区段查找与指定的（地址，符号）匹配的DWORD地址，并将对应地址的值命名
    - [IDA-stack_strings_deobfuscator_1](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/stack_strings_deobfuscator_1.py) 反混淆栈字符串
- [**80**星][3m] [Py] [takahiroharuyama/ida_haru](https://github.com/takahiroharuyama/ida_haru) 多工具
    - [bindiff](https://github.com/takahiroharuyama/ida_haru/blob/master/bindiff/README.org) 使用BinDiff对多个二进制文件进行对比，可多达100个
    - [eset_crackme](https://github.com/takahiroharuyama/ida_haru/blob/master/eset_crackme/README.org) ESET CrackMe driver VM loader/processor
    - [fn_fuzzy](https://github.com/takahiroharuyama/ida_haru/blob/master/fn_fuzzy/README.org) 快速二进制文件对比
    - [stackstring_static](https://github.com/takahiroharuyama/ida_haru/blob/master/stackstring_static/README.org) 静态恢复栈上的字符串
- [**73**星][9m] [Py] [secrary/ida-scripts](https://github.com/secrary/ida-scripts) 多脚本
    - [dumpDyn](https://github.com/secrary/ida-scripts/blob/master/dumpDyn/README.md) 保存动态分配并执行的代码的相关信息：注释、名称、断点、函数等，之后此代码在不同基址执行时使保存内容依然可用
    - [idenLib](https://github.com/secrary/ida-scripts/blob/master/idenLib/README.md) 库函数识别
    - [IOCTL_decode](https://github.com/secrary/ida-scripts/blob/master/IOCTL_decode.py) Windows驱动的IO控制码
    - [XORCheck](https://github.com/secrary/ida-scripts/blob/master/XORCheck.py) 
- [**60**星][2y] [Py] [tmr232/idabuddy](https://github.com/tmr232/idabuddy) 逆向滴好盆友??
- [**59**星][2y] [C++] [alexhude/loadprocconfig](https://github.com/alexhude/loadprocconfig) 加载处理器配置文件
- [**57**星][1m] [Py] [williballenthin/idawilli](https://github.com/williballenthin/idawilli) IDA Pro 资源、脚本和配置文件等
    - [hint_calls](https://github.com/williballenthin/idawilli/blob/master/plugins/hint_calls/readme.md) 以Hint的形式战士函数引用的call和字符串
    - [dynamic_hints](https://github.com/williballenthin/idawilli/blob/master/plugins/dynamic_hints/readme.md) 演示如何为动态数据提供自定义hint的示例插件
    - [add_segment](https://github.com/williballenthin/idawilli/tree/master/scripts/add_segment) 将已存在文件的内容添加为新的segment
    - [color](https://github.com/williballenthin/idawilli/tree/master/scripts/color) 对指令进行着色
    - [find_ptrs](https://github.com/williballenthin/idawilli/tree/master/scripts/find_ptrs) 扫描.text区段查找可能为指针的值,并进行标记
    - [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn) 创建yara规则，匹配当前函数的basic block
- [**54**星][1y] [Py] [zardus/idalink](https://github.com/zardus/idalink) 使用IDA API时保证不卡界面. 在后台启动与界面脱离IDA CLI会话, 再使用RPyC连接界面
- [**52**星][3y] [C++] [sektioneins/wwcd](https://github.com/sektioneins/wwcd) Capstone powered IDA view
- [**51**星][2y] [Py] [cseagle/ida_clemency](https://github.com/cseagle/ida_clemency) IDA cLEMENCy Tools
- [**50**星][2m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - 重复区段: [工具/导入导出&与其他工具交互/Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA多个脚本
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构
- [**49**星][11m] [Py] [agustingianni/utilities](https://github.com/agustingianni/utilities) 多个IDAPython脚本
- [**47**星][3y] [Py] [jjo-sec/idataco](https://github.com/jjo-sec/idataco) 多功能
- [**45**星][7y] [Py] [carlosgprado/milf](https://github.com/carlosgprado/milf) IDA瑞士军刀
    - [milf](https://github.com/carlosgprado/MILF/blob/master/milf.py) 辅助漏洞挖掘
- [**40**星][6m] [Visual Basic] [dzzie/re_plugins](https://github.com/dzzie/re_plugins) 逆向插件收集
    - [IDASrvr](https://github.com/dzzie/re_plugins/tree/master/IDASrvr) wm_copydata IPC 服务器，通过WM_COPYDATA机制监听远程消息， 可从其他进程中想IDA发送命令，查询数据，控制接口显示
    - [IDA_JScript](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript) 通过IDASrvr，使用JavaScript编写IDA脚本（依赖ActiveX）
    - [IDA_JScript_w_DukDbg](https://github.com/dzzie/re_plugins/tree/master/IDA_JScript_w_DukDbg) IDA_JScript进阶版
    - [IDASrvr2](https://github.com/dzzie/re_plugins/tree/master/IDASrvr2) IDASrvr进阶版，添加x64支持
    - [IdaUdpBridge](https://github.com/dzzie/re_plugins/tree/master/IdaUdpBridge) 
    - [IdaVbScript](https://github.com/dzzie/re_plugins/tree/master/IdaVbScript) 
    - [OllySrvr](https://github.com/dzzie/re_plugins/tree/master/OllySrvr) 
    - [Olly_hittrace](https://github.com/dzzie/re_plugins/tree/master/Olly_hittrace) 
    - [Olly_module_bpx](https://github.com/dzzie/re_plugins/tree/master/Olly_module_bpx) 
    - [Olly_vbscript](https://github.com/dzzie/re_plugins/tree/master/Olly_vbscript) 
    - [PyIDAServer](https://github.com/dzzie/re_plugins/tree/master/PyIDAServer) 测试在IDA中运行IPC服务器
    - [Wingraph32](https://github.com/dzzie/re_plugins/tree/master/Wingraph32) 
    - [rabc_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/rabc_gui) 
    - [swfdump_gui](https://github.com/dzzie/re_plugins/tree/master/flash_tools/swfdump_gui) 
    - [gleegraph](https://github.com/dzzie/re_plugins/tree/master/gleegraph) 
    - [hidden_strings](https://github.com/dzzie/re_plugins/tree/master/misc_tools/hidden_strings) 
    - [memdump_conglomerate](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_conglomerate) 
    - [memdump_embedder](https://github.com/dzzie/re_plugins/tree/master/misc_tools/memdump_embedder) 
    - [rtf_hexconvert](https://github.com/dzzie/re_plugins/tree/master/misc_tools/rtf_hexconvert) 
    - [uGrapher](https://github.com/dzzie/re_plugins/tree/master/uGrapher) 
    - [wininet_hooks](https://github.com/dzzie/re_plugins/tree/master/wininet_hooks) Hook以下API调用并记录关键信息：HttpOpenRequest,InternetConnect,InternetReadFile,InternetCrackUrl,HttpSendRequest
- [**40**星][2y] [Py] [mxmssh/idametrics](https://github.com/mxmssh/idametrics) 收集x86体系结构的二进制可执行文件的静态软件复杂性度量
- [**40**星][4y] [C++] [nihilus/guid-finder](https://github.com/nihilus/guid-finder) 查找GUID/UUID
- [**38**星][2y] [Py] [saelo/ida_scripts](https://github.com/saelo/ida_scripts) 多脚本
    - [kernelcache](https://github.com/saelo/ida_scripts/blob/master/kernelcache.py) 识别并重命名iOS kernelcache函数stub。ARM64 Only
    - [ssdt](https://github.com/saelo/ida_scripts/blob/master/ssdt.py) 解析Windows内核中的syscall表
- [**34**星][4y] [Py] [madsc13ntist/idapython](https://github.com/madsc13ntist/idapython) IDAPython脚本收集（无文档）
- [**32**星][5y] [Py] [iphelix/ida-pomidor](https://github.com/iphelix/ida-pomidor) 在长时间的逆向中保存注意力和效率
- [**28**星][5m] [Py] [enovella/re-scripts](https://github.com/enovella/re-scripts) IDA/Ghidra/Radare2脚本收集（无文档）
- [**28**星][1y] [Py] [xyzz/vita-ida-physdump](https://github.com/xyzz/vita-ida-physdump) None
- [**27**星][1y] [Py] [daniel_plohmann/simplifire.idascope](https://bitbucket.org/daniel_plohmann/simplifire.idascope) 简化恶意代码分析
- [**26**星][5y] [Py] [bastkerg/recomp](https://github.com/bastkerg/recomp) IDA recompiler（无文档）
- [**26**星][7m] [C++] [offlinej/ida-rpc](https://github.com/offlinej/ida-rpc) Discord rich presence plugin for IDA Pro 7.0
- [**25**星][3y] [Py] [zyantific/continuum](https://github.com/zyantific/continuum) Plugin adding multi-binary project support to IDA Pro (WIP)
- [**23**星][9m] [C++] [trojancyborg/ida_jni_rename](https://github.com/trojancyborg/ida_jni_rename) IDA JNI调用重命名
- [**22**星][5y] [Py] [nihilus/idascope](https://github.com/nihilus/idascope) 辅助恶意代码逆向（Bitbucket上的代码较新）
- [**22**星][4y] [Py] [onethawt/idapyscripts](https://github.com/onethawt/idapyscripts) IDAPython脚本
    - [DataXrefCounter ](https://github.com/onethawt/idapyscripts/blob/master/dataxrefcounter.py) 枚举指定区段的所有交叉引用，计算使用频率
- [**22**星][3y] [C++] [patois/idaplugins](https://github.com/patois/idaplugins) Random IDA scripts, plugins, example code (some of it may be old and not working anymore)
- [**21**星][2m] [Py] [nlitsme/idascripts](https://github.com/nlitsme/idascripts) 枚举多种类型数据：Texts/NonFuncs/...
- [**21**星][1m] [Py] [rceninja/re-scripts](https://github.com/rceninja/re-scripts) None
    - [Hyperv-Scripts](https://github.com/rceninja/re-scripts/tree/master/scripts/Hyperv-Scripts) 
    - [IA32-MSR-Decoder](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-MSR-Decoder) 查找并解码所有的MSR码
    - [IA32-VMX-Helper](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-VMX-Helper) 查找并解码所有的MSR/VMCS码
- [**20**星][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) IDAPython脚本
- [**20**星][2y] [C#] [zoebear/radia](https://github.com/zoebear/radia) 创建一个用于可视化代码的交互式、沉浸式环境，辅助二进制文件逆向
- [**20**星][3y] [Py] [ztrix/idascript](https://github.com/ztrix/idascript) Full functional idascript with stdin/stdout handled
- [**20**星][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) ida python scripts
- [**20**星][23d] [Py] [mephi42/ida-kallsyms](https://github.com/mephi42/ida-kallsyms) None
- [**19**星][8m] [Py] [yellowbyte/reverse-engineering-playground](https://github.com/yellowbyte/reverse-engineering-playground) 逆向脚本收集，包括：IDAPython、文件分析、文件格式分析、文件系统分析、Shellcode分析
- [**18**星][1y] [Py] [a1ext/ida-embed-arch-disasm](https://github.com/a1ext/ida-embed-arch-disasm) 使IDA可在32位数据库中反汇编x64代码(WOW64) 
- [**17**星][1y] [Py] [honeybadger1613/etm_displayer](https://github.com/honeybadger1613/etm_displayer) IDA Pro плагин для отображения результата Coresight ETM трассировки perf'а
- [**16**星][4y] [fabi/idacsharp](https://github.com/fabi/idacsharp) C# 'Scripts' for IDA 6.6+ based on
- [**15**星][7m] [CMake] [google/idaidle](https://github.com/google/idaidle) 如果用户将实例闲置时间过长，则会警告用户。在预定的空闲时间后，该插件首先发出警告，然后再保存当前的disassemlby数据库并关闭IDA
- [**14**星][4y] [C++] [nihilus/fast_idb2sig_and_loadmap_ida_plugins](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins) 2个插件
    - [LoadMap](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/tree/master/LoadMap) 
    - [idb2sig](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/blob/master/idb2sig/ReadMe.txt) 
- [**13**星][2y] [Py] [cisco-talos/pdata_check](https://github.com/cisco-talos/pdata_check) 根据pdata节和运行时函数的最后一条指令识别异常运行时。
- [**13**星][11m] [C++] [nihilus/graphslick](https://github.com/nihilus/graphslick) IDA Plugin - GraphSlick
- [**13**星][1y] [Py] [cxm95/ida_wrapper](https://github.com/cxm95/ida_wrapper) An IDA_Wrapper for linux, shipped with an Function Identifier. It works well with Driller on static linked binaries.
- [**12**星][1y] [Assembly] [gabrielravier/cave-story-decompilation](https://github.com/gabrielravier/cave-story-decompilation) 使用IDA反编译的游戏洞窟物語（Cave Story）
- [**11**星][2y] [Py] [0xddaa/iddaa](https://github.com/0xddaa/iddaa) idapython scripts
- [**11**星][5y] [Py] [dshikashio/idarest](https://github.com/dshikashio/idarest) Expose some basic IDA Pro interactions through a REST API for JSONP
- [**11**星][8m] [C++] [ecx86/ida7-supportlib](https://github.com/ecx86/ida7-supportlib) IDA-SupportLib library by sirmabus, ported to IDA 7
- [**10**星][4y] [C++] [revel8n/spu3dbg](https://github.com/revel8n/spu3dbg) 调试anergistic SPU emulator
- [**9**星][4y] [Py] [nfarrar/ida-colorschemes](https://github.com/nfarrar/ida-colorschemes) A .clr colorscheme generator for IDA Pro 6.4+.
- [**9**星][5y] [Ruby] [rogwfu/plympton](https://github.com/rogwfu/plympton) Library to work with yaml exported IDA Pro information and run statistics
- [**9**星][8m] [Py] [0xcpu/relieve](https://github.com/0xcpu/relieve) 逆向/恶意代码分析脚本
- [**8**星][5y] [Py] [daniel_plohmann/idapatchwork](https://bitbucket.org/daniel_plohmann/idapatchwork) None
- [**8**星][2y] [C++] [ecx86/ida7-segmentselect](https://github.com/ecx86/ida7-segmentselect) IDA-SegmentSelect library by sirmabus, ported to IDA 7
- [**8**星][6d] [Py] [lanhikari22/gba-ida-pseudo-terminal](https://github.com/lanhikari22/gba-ida-pseudo-terminal) IDAPython tools to aid with analysis, disassembly and data extraction using IDA python commands, tailored for the GBA architecture at some parts
- [**8**星][10d] [C++] [nlitsme/idcinternals](https://github.com/nlitsme/idcinternals) 研究IDC脚本的内部表现形式
- [**8**星][3y] [Py] [pwnslinger/ibt](https://github.com/pwnslinger/ibt) IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction
- [**8**星][2y] [C++] [shazar14/idadump](https://github.com/shazar14/idadump) An IDA Pro script to verify binaries found in a sample and write them to disk
- [**7**星][2y] [Py] [swackhamer/ida_scripts](https://github.com/swackhamer/ida_scripts) IDAPython脚本（无文档）
- [**7**星][8m] [Py] [techbliss/ida_pro_http_ip_geolocator](https://github.com/techbliss/ida_pro_http_ip_geolocator) ida_pro_http_ip_geolocator：IDA 插件，查找网址并解析为 ip，通过Google 地图查看
- [**7**星][5y] [Py] [techbliss/processor-changer](https://github.com/techbliss/processor-changer) 修改处理器（需重新打开IDA）
- [**7**星][1y] [C++] [tenable/mida](https://github.com/tenable/mida) 提取RPC接口，重新创建关联的IDL文件
- [**6**星][2y] [CMake] [elemecca/cmake-ida](https://github.com/elemecca/cmake-ida) 使用CMake构建IDA Pro模块
- [**6**星][2y] [Py] [fireundubh/ida7-alleycat](https://github.com/fireundubh/ida7-alleycat) Alleycat plugin by devttys0, ported to IDA 7
- [**6**星][7m] [Py] [geosn0w/dumpanywhere64](https://github.com/geosn0w/dumpanywhere64) An IDA (Interactive Disassembler) script that can save a chunk of binary from an address.
- [**6**星][1y] [C++] [ecx86/ida7-hexrays-invertif](https://github.com/ecx86/ida7-hexrays-invertif) Hex-Rays Invert if statement plugin for IDA 7.0
- [**5**星][3y] [Py] [andreafioraldi/idavshelp](https://github.com/andreafioraldi/idavshelp) 在IDA中集成VS的帮助查看器
- [**5**星][4m] [Py] [fdiskyou/ida-plugins](https://github.com/fdiskyou/ida-plugins) IDAPython脚本（无文档）
    - [banned_functions](https://github.com/fdiskyou/ida-plugins/blob/master/banned_functions.py) 
- [**5**星][1y] [C++] [lab313ru/m68k_fixer](https://github.com/lab313ru/m68k_fixer) IDA Pro plugin fixer for m68k
- [**5**星][5y] [C#] [npetrovski/ida-smartpatcher](https://github.com/npetrovski/ida-smartpatcher) IDA apply patch GUI
- [**5**星][4y] [Py] [tmr232/tarkus](https://github.com/tmr232/tarkus) Plugin Manager for IDA Pro
- [**4**星][1m] [Py] [gitmirar/idaextapi](https://github.com/gitmirar/idaextapi) IDA API utlitites
- [**4**星][3y] [Py] [hustlelabs/joseph](https://github.com/hustlelabs/joseph) IDA Viewer Plugins
- [**4**星][1y] [savagedd/samp-server-idb](https://github.com/savagedd/samp-server-idb) None
- [**4**星][1m] [Py] [spigwitmer/golang_struct_builder](https://github.com/spigwitmer/golang_struct_builder) IDA 7.0+ script that auto-generates structs and interfaces from runtime metadata found in golang binaries
- [**3**星][9m] [Py] [gdataadvancedanalytics/ida-python](https://github.com/gdataadvancedanalytics/ida-python) None
- [**3**星][2y] [Py] [ypcrts/ida-pro-segments](https://github.com/ypcrts/ida-pro-segments) It's very hard to load multiple files in the IDA GUI without it exploding. This makes it easy.
- [**3**星][1y] [abarbatei/ida-utils](https://github.com/abarbatei/ida-utils) links, information and helper scripts for IDA Pro
- [**2**星][2y] [C++] [ecx86/ida7-oggplayer](https://github.com/ecx86/ida7-oggplayer) IDA-OggPlayer library by sirmabus, ported to IDA 7
- [**2**星][2y] [Py] [mayl8822/ida](https://github.com/mayl8822/ida) 快速执行谷歌/百度/Bing搜索
- [**2**星][5y] [C++] [nihilus/ida-x86emu](https://github.com/nihilus/ida-x86emu) x86模拟执行
- [**2**星][4y] [Py] [nihilus/idapatchwork](https://github.com/nihilus/idapatchwork) Stitching against malware families with IDA Pro
- [**2**星][2y] [Py] [sbouber/idaplugins](https://github.com/sbouber/idaplugins) None
- [**2**星][1m] [Py] [psxvoid/idapython-debugging-dynamic-enrichment](https://github.com/psxvoid/idapython-debugging-dynamic-enrichment) None
- [**1**星][2y] [Py] [andreafioraldi/idamsdnhelp](https://github.com/andreafioraldi/idamsdnhelp) 打开MSDN帮助搜索页
- [**1**星][1y] [Py] [farzonl/idapropluginlab4](https://github.com/farzonl/idapropluginlab4) An ida pro plugin that tracks def use chains of a given x86 binary.
- [**1**星][1m] [Py] [voidsec/ida-helpers](https://github.com/voidsec/ida-helpers) Collection of IDA helpers


***


## <a id="fb4f0c061a72fc38656691746e7c45ce"></a>结构体&&类的检测&&创建&&恢复


### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>未分类


- [**924**星][10d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [工具/污点分析&&符号执行](#34ac84853604a7741c61670f2a075d20) |
- [**649**星][4m] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) 结构体和类重建插件
- [**168**星][12m] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) 使用IDA Pro重建iOS内核缓存的C++类
    - 重复区段: [工具/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/内核缓存](#82d0fa2d6934ce29794a651513934384) |
- [**138**星][4y] [C++] [nihilus/hexrays_tools](https://github.com/nihilus/hexrays_tools) 辅助结构体定义和虚函数检测
- [**103**星][2m] [Py] [lucasg/findrpc](https://github.com/lucasg/findrpc)  从二进制文件中提取内部的RPC结构体
- [**4**星][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) 在指定地址区间内搜索字符串，并将其映射为C结构体
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


### <a id="4900b1626f10791748b20630af6d6123"></a>C++类&&虚表


- [**595**星][2m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
    - 重复区段: [工具/调试&&动态运行&动态数据/调试数据](#b31acf6c84a9506066d497af4e702bf5) |
        <details>
        <summary>查看详情</summary>


        ## 静态部分: 
        - 检测非直接调用
        - 利用条件断点, Hook非直接调用的值赋值过程
        
        ## 动态 部分
        - 创建虚表结构
        - 重命名函数和虚表地址
        - 给反汇编非直接调用添加结构偏移
        - 给非直接调用到虚表之间添加交叉引用
        
        ## 使用
        - File -> Script File -> Main.py(设置断点) -> IDA调试器执行
        </details>


- [**168**星][8m] [C++] [ecx86/classinformer-ida7](https://github.com/ecx86/classinformer-ida7) ClassInformer backported for IDA Pro 7.0
- [**128**星][2y] [Py] [nccgroup/susanrtti](https://github.com/nccgroup/SusanRTTI) RTTI解析插件
- [**91**星][1y] [C++] [rub-syssec/marx](https://github.com/rub-syssec/marx) 揭示C++程序中的类继承结构
    - [IDA导出](https://github.com/rub-syssec/marx/blob/master/ida_export/export.py) 
    - [IDA导入插件](https://github.com/rub-syssec/marx/tree/master/ida_import) 
    - [核心代码](https://github.com/rub-syssec/marx/tree/master/src) 
- [**68**星][7y] [C] [nektra/vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin) Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
- [**35**星][5y] [C++] [nihilus/ida_classinformer](https://github.com/nihilus/ida_classinformer) IDA ClassInformer PlugIn
- [**32**星][2y] [Py] [krystalgamer/dec2struct](https://github.com/krystalgamer/dec2struct) 使用类定义/声明文件，在 IDA 中轻松创建虚表
- [**16**星][2y] [C++] [mwl4/ida_gcc_rtti](https://github.com/mwl4/ida_gcc_rtti) Class informer plugin for IDA which supports parsing GCC RTTI




***


## <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>收集


- [**1732**星][1m] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) IDA插件收集
- [**356**星][8m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) IDA x64DBG OllyDBG 插件收集
- [**10**星][1y] [Py] [ecx86/ida-scripts](https://github.com/ecx86/ida-scripts) IDA Pro/Hex-Rays configs, scripts, and plugins收集


***


## <a id="fabf03b862a776bbd8bcc4574943a65a"></a>外观&&主题


- [**712**星][5m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) 皮肤插件
- [**257**星][7y] [eugeneching/ida-consonance](https://github.com/eugeneching/ida-consonance) 黑色皮肤插件
- [**103**星][5m] [CSS] [0xitx/ida_nightfall](https://github.com/0xitx/ida_nightfall) 黑色主题插件
- [**58**星][7y] [gynophage/solarized_ida](https://github.com/gynophage/solarized_ida) Solarized黑色主题
- [**10**星][7y] [Py] [luismiras/ida-color-scripts](https://github.com/luismiras/ida-color-scripts) 导入导出颜色主题
- [**8**星][2y] [CSS] [gbps/x64dbg-consonance-theme](https://github.com/gbps/x64dbg-consonance-theme) 黑色的x64dbg主题
- [**6**星][5y] [Py] [techbliss/ida-styler](https://github.com/techbliss/ida-styler) 修改IDA样式
- [**3**星][1m] [rootbsd/ida_pro_zinzolin_theme](https://github.com/rootbsd/ida_pro_zinzolin_theme) zinzolin主题
- [**1**星][12m] [C] [albertzsigovits/idc-dark](https://github.com/albertzsigovits/idc-dark) A dark-mode color scheme for Hex-Rays IDA using idc


***


## <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>固件&&嵌入式设备


- [**5105**星][10d] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) 固件分析工具（命令行+IDA插件）
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**483**星][3m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) 自动分析嵌入式设备的固件
- [**173**星][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) Duo 实验室使用的IDAPython 脚本收集
    - 重复区段: [工具/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/未分类](#8530752bacfb388f3726555dc121cb1a) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**90**星][14d] [Py] [pagalaxylab/vxhunter](https://github.com/PAGalaxyLab/vxhunter) 用于分析基于VxWorks的嵌入式设备的工具集
    - [R2](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_r2_py2.py) 
    - [IDA插件](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_ida.py) 
    - [Ghidra插件](https://github.com/PAGalaxyLab/vxhunter/tree/master/firmware_tools/ghidra) 


***


## <a id="02088f4884be6c9effb0f1e9a3795e58"></a>签名(FLIRT等)&&比较(Diff)&&匹配


### <a id="cf04b98ea9da0056c055e2050da980c1"></a>未分类


- [**416**星][19d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [工具/作为辅助&&构成其他的一环](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**147**星][12m] [C++] [ajkhoury/sigmaker-x64](https://github.com/ajkhoury/SigMaker-x64) IDA Pro 7.0 compatible SigMaker plugin
- [**128**星][1y] [Py] [cisco-talos/bass](https://github.com/cisco-talos/bass) 从先前生成的恶意软件集群的样本中自动生成AV签名
- [**71**星][4y] [Py] [icewall/bindifffilter](https://github.com/icewall/bindifffilter) IDA Pro plugin making easier work on BinDiff results
- [**70**星][5y] [Py] [arvinddoraiswamy/slid](https://github.com/arvinddoraiswamy/slid) 静态链接库检测
- [**50**星][1m] [Py] [vrtadmin/first-plugin-ida](https://github.com/vrtadmin/first-plugin-ida) 函数识别与签名恢复工具
- [**45**星][1y] [Py] [l4ys/idasignsrch](https://github.com/l4ys/idasignsrch) 签名搜索
- [**33**星][3y] [Py] [g4hsean/binauthor](https://github.com/g4hsean/binauthor) 识别未知二进制文件的作者
- [**31**星][1y] [Py] [cisco-talos/casc](https://github.com/cisco-talos/casc) 在IDA的反汇编和字符串窗口中, 辅助创建ClamAV NDB 和 LDB签名
- [**25**星][2y] [LLVM] [syreal17/cardinal](https://github.com/syreal17/cardinal) Similarity Analysis to Defeat Malware Compiler Variations
- [**23**星][4m] [Py] [xorpd/fcatalog_server](https://github.com/xorpd/fcatalog_server) Functions Catalog
- [**21**星][3y] [Py] [xorpd/fcatalog_client](https://github.com/xorpd/fcatalog_client) fcatalog idapython client
- [**18**星][5y] [Py] [zaironne/snippetdetector](https://github.com/zaironne/snippetdetector) IDA Python scripts project for snippets detection
- [**16**星][8y] [C++] [alexander-pick/idb2pat](https://github.com/alexander-pick/idb2pat) idb2pat plugin, fixed to work with IDA 6.2
- [**14**星][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA签名文件，iPhone基带逆向
    - 重复区段: [工具/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/未分类](#8530752bacfb388f3726555dc121cb1a) |
- [**3**星][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) 对比Linux和Windows二进制文件，对Windows文件未命名的函数进行自动重命名
    - 重复区段: [工具/函数相关/重命名&&前缀&&标记](#73813456eeb8212fd45e0ea347bec349) |
- [**0**星][1y] [Py] [gh0st3rs/idaprotosync](https://github.com/gh0st3rs/idaprotosync) 在2个或多个函数中识别函数原型


### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT签名


#### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRT签名收集


- [**589**星][5d] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**303**星][4m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database
- [**5**星][7m] [cloudwindby/ida-pro-sig](https://github.com/cloudwindby/ida-pro-sig) IDA PRO FLIRT signature files MSVC2017的sig文件


#### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRT签名生成


- [**58**星][9m] [Py] [push0ebp/allirt](https://github.com/push0ebp/allirt) Tool that converts All of libc to signatures for IDA Pro FLIRT Plugin. and utility make sig with FLAIR easily
- [**42**星][7m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - 重复区段: [工具/导入导出&与其他工具交互/Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |




### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match工具


- [**1525**星][18d] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) program diffing
- [**353**星][3m] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) Karta - source code assisted fast binary matching plugin for IDA
- [**328**星][11m] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.
- [**136**星][12m] [Py] [nirizr/rematch](https://github.com/nirizr/rematch) REmatch, a complete binary diffing framework that is free and strives to be open source and community driven.
- [**94**星][6m] [Visual Basic] [dzzie/idacompare](https://github.com/dzzie/idacompare) 汇编级别对比工具
- [**74**星][4y] [C] [nihilus/ida_signsrch](https://github.com/nihilus/ida_signsrch) signsrch签名匹配
- [**72**星][5y] [Py] [binsigma/binsourcerer](https://github.com/binsigma/binsourcerer) 反汇编与源码匹配
- [**71**星][3y] [vrtadmin/first](https://github.com/vrtadmin/first) 函数识别和签名恢复, 带服务器
- [**52**星][5y] [C++] [filcab/patchdiff2](https://github.com/filcab/patchdiff2) IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
- [**14**星][3y] [Py] [0x00ach/idadiff](https://github.com/0x00ach/idadiff) IDAPython脚本，使用@Heurs MACHOC algorithm (https://github.com/ANSSI-FR/polichombr)算法创建二进制文件的CFG Hash，与其他样本对比。如果发现1-1关系，则重命名
- [**14**星][5y] [C++] [binsigma/binclone](https://github.com/binsigma/binclone) 检测恶意代码中的相似代码


### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**424**星][20d] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [工具/加密解密](#06d2caabef97cf663bd29af2b1fe270c) |
- [**92**星][26d] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/Hyara) 辅助编写Yara规则
    - [IDA插件](https://github.com/hy00un/hyara/tree/master/IDA%20Plugin) 
    - [BinaryNinja插件](https://github.com/hy00un/hyara/tree/master/BinaryNinja%20Plugin) 
- [**92**星][26d] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
- [**81**星][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) 使用Yara规则扫描二进制文件
- [**16**星][10m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) 针对已编译Yara规则文件的Loader&&Processor
    - 重复区段: [工具/针对特定分析目标/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**14**星][1y] [Py] [alexander-hanel/ida_yara](https://github.com/alexander-hanel/ida_yara) 使用Yara扫描IDB数据
- [**14**星][1y] [Py] [souhailhammou/idaray-plugin](https://github.com/souhailhammou/idaray-plugin) IDARay is an IDA Pro plugin that matches the database against multiple YARA files which themselves may contain multiple rules.




***


## <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB操作


- [**312**星][5m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb) idb 文件解析和分析工具
- [**144**星][8d] [Py] [nccgroup/idahunt](https://github.com/nccgroup/idahunt) 在IDA外部使用IDAPython脚本, 批量创建/读取/解析IDB文件, 可编写自己的IDB分析脚本,命令行工具,
- [**84**星][4m] [C++] [nlitsme/idbutil](https://github.com/nlitsme/idbutil) 从 IDA 数据库中提取数据，支持 idb 及 i64
- [**78**星][2m] [Py] [nlitsme/pyidbutil](https://github.com/nlitsme/pyidbutil) 读取IDB数据库
- [**18**星][1y] [Py] [kkhaike/tinyidb](https://github.com/kkhaike/tinyidb) 从巨型IDB数据库中导出用户数据
- [**0**星][4y] [C] [hugues92/idaextrapassplugin](https://github.com/hugues92/idaextrapassplugin) 修复与清理IDB数据库


***


## <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>协作逆向&&多人操作相同IDB文件


- [**504**星][10m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) 多人协作插件
- [**257**星][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) 利用Git版本控制，同步多人对相同二进制文件的修改
- [**88**星][5y] [Py] [cubicalabs/idasynergy](https://github.com/cubicalabs/idasynergy) 集成了版本控制系统(svn)的IDA插件
- [**71**星][14d] [C++] [cseagle/collabreate](https://github.com/cseagle/collabreate) Hook IDA的事件通知，将事件涉及的修改内容广播到中心服务器，中心服务器转发给其他分析相同文件的用户
- [**4**星][2y] [Py] [argussecurity/psida](https://bitbucket.org/socialauth/login/atlassianid/?next=%2Fargussecurity%2Fpsida) IDAPython脚本收集，当前只有协作逆向的脚本


***


## <a id="f7d311685152ac005cfce5753c006e4b"></a>与调试器同步&&通信&&交互


- [**448**星][15d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) 在反汇编工具和调试器之间同步调试会话
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**285**星][9m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) 在IDA和调试器之间无缝同步Label/注释等
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 
- [**168**星][11m] [Py] [andreafioraldi/idangr](https://github.com/andreafioraldi/idangr) 在IDA中使用angrdbg调试器进行调试
- [**128**星][2y] [Py] [comsecuris/gdbida](https://github.com/comsecuris/gdbida) 使用GDB调试时，在IDA中自动跟随当前GDB的调试位置
    - [IDA插件](https://github.com/comsecuris/gdbida/blob/master/ida_gdb_bridge.py) 
    - [GDB脚本](https://github.com/comsecuris/gdbida/blob/master/gdb_ida_bridge_client.py) 
- [**98**星][4y] [C++] [quarkslab/qb-sync](https://github.com/quarkslab/qb-sync) 使用调试器调试时，自动在IDA中跟随调试位置
    - [GDB插件](https://github.com/quarkslab/qb-sync/tree/master/ext_gdb) 
    - [IDA插件](https://github.com/quarkslab/qb-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/quarkslab/qb-sync/tree/master/ext_lldb) 
    - [OD2](https://github.com/quarkslab/qb-sync/tree/master/ext_olly2) 
    - [WinDbg](https://github.com/quarkslab/qb-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/quarkslab/qb-sync/tree/master/ext_x64dbg) 
- [**43**星][3m] [JS] [sinakarvandi/windbg2ida](https://github.com/sinakarvandi/windbg2ida) 在IDA中显示Windbg调试的每个步骤
    - [Windbg脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/windbg2ida.js) JavaScript
    - [IDA脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/IDAScript.py) 
- [**36**星][9m] [Py] [anic/ida2pwntools](https://github.com/anic/ida2pwntools) IDA插件，远程连接pwntools启动的程序进行pwn调试
- [**28**星][1y] [Py] [iweizime/dbghider](https://github.com/iweizime/dbghider) 向被调试进程隐藏IDA调试器
- [**17**星][7y] [Py] [rmadair/windbg2ida](https://github.com/rmadair/windbg2ida) 将WinDBG中的调试trace导入到IDA


***


## <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>导入导出&与其他工具交互


### <a id="8ad723b704b044e664970b11ce103c09"></a>未分类


- [**159**星][25d] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) x64dbg插件，用于IDA数据导入导出
- [**143**星][25d] [C++] [alschwalm/dwarfexport](https://github.com/alschwalm/dwarfexport) Export dwarf debug information from IDA Pro
- [**95**星][2y] [Py] [robindavid/idasec](https://github.com/robindavid/idasec) IDA插件，与Binsec 平台进行交互
- [**67**星][11m] [Py] [lucasg/idamagnum](https://github.com/lucasg/idamagnum) 在IDA中向MagnumDB发起请求, 查询枚举常量可能的值
- [**58**星][5d] [Py] [binaryanalysisplatform/bap-ida-python](https://github.com/binaryanalysisplatform/bap-ida-python) IDAPython脚本，在IDA中集成BAP
- [**35**星][5y] [Py] [siberas/ida2sym](https://github.com/siberas/ida2sym) IDAScript to create Symbol file which can be loaded in WinDbg via AddSyntheticSymbol
- [**29**星][5y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - 重复区段: [工具/针对特定分析目标/PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**28**星][4m] [C++] [thalium/idatag](https://github.com/thalium/idatag) IDA plugin to explore and browse tags
- [**19**星][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) 在IDA中集成angr二进制分析框架
- [**16**星][4y] [C++] [m417z/mapimp](https://github.com/m417z/mapimp) This is an OllyDbg plugin which will help you to import map files exported by IDA, Dede, IDR, Microsoft and Borland linkers.
- [**16**星][4y] [Py] [danielmgmi/virusbattle-ida-plugin](https://github.com/danielmgmi/virusbattle-ida-plugin) The plugin is an integration of Virus Battle API to the well known IDA Disassembler.
- [**8**星][7y] [C++] [patois/madnes](https://github.com/patois/madnes) 从IDB中导出符号和名称，使可在FCEUXD SP中导入
- [**3**星][1y] [Py] [r00tus3r/differential_debugging](https://github.com/r00tus3r/differential_debugging) Differential debugging using IDA Python and GDB


### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**288**星][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) 在IDA中集成Ghidra反编译器
- [**235**星][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) 使IDA和Ghidra脚本通用, 无需修改
- [**85**星][3m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) 通过REST API暴露Ghidra分析服务, 也是GhIDA的后端
- [**47**星][29d] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
- [**42**星][7m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/FLIRT签名/FLIRT签名生成](#a9a63d23d32c6c789ca4d2e146c9b6d0) |


### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**378**星][11d] [C++] [google/binexport](https://github.com/google/binexport) 将反汇编以Protocol Buffer的形式导出为PostgreSQL数据库, 导入到BinNavi中使用
- [**213**星][3y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) 从IDA中导出反汇编信息, 导入到binnavi中使用
- [**25**星][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) This python/jython script is used as plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.


### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja


- [**67**星][7m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) IDA和Binja实时同步插件
- [**60**星][5m] [Py] [zznop/bnida](https://github.com/zznop/bnida) 4个脚本，在IDA和BinaryNinja间交互数据
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**星][4m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) Binary Ninja插件，从IDA中导入IDC数据库转储


### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2


- [**125**星][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[工具/函数相关/未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**123**星][22d] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa


### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida


- [**129**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - 重复区段: [工具/调试&&动态运行&动态数据/DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**81**星][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) 在IDA中使用Frida, 主要用于追踪函数
- [**50**星][2m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) 010Editor/BurpSuite/Frida/IDA等多个工具的多个脚本
    - 重复区段: [工具/未分类](#c39a6d8598dde6abfeef43faf931beb5) |
    - [010Editor](https://github.com/lich4/personal_script/tree/master/010Editor_Script) 010Editor的多个脚本
    - [ParamChecker](https://github.com/lich4/personal_script/tree/master/BurpSuite_Script) Burp插件
    - [Frida](https://github.com/lich4/personal_script/tree/master/Frida_script) Frida多个脚本
    - [IDA](https://github.com/lich4/personal_script/tree/master/IDA_Script) IDA多个脚本
    - [IDA-read_unicode.py](https://github.com/lich4/personal_script/blob/master/IDA_Script/read_unicode.py) IDA插件，识别程序中的中文字符
    - [IDA-add_xref_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_xref_for_macho.py) 辅助识别Objective-C成员函数的caller和callee
    - [IDA-add_info_for_androidgdb](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_info_for_androidgdb.py) 使用gdbserver和IDA调试Android时，读取module列表和segment
    - [IDA-trace_instruction](https://github.com/lich4/personal_script/blob/master/IDA_Script/trace_instruction.py) 追踪指令流
    - [IDA-detect_ollvm](https://github.com/lich4/personal_script/blob/master/IDA_Script/detect_ollvm.py) 检测OLLVM，在某些情况下修复（Android/iOS）
    - [IDA-add_block_for_macho](https://github.com/lich4/personal_script/blob/master/IDA_Script/add_block_for_macho.py) 分析macho文件中的block结构


### <a id="dd0332da5a1482df414658250e6357f8"></a>IntelPin


- [**133**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [工具/调试&&动态运行&动态数据/DBI数据](#0fbd352f703b507853c610a664f024d1) |[工具/漏洞/未分类](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**43**星][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin




***


## <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>针对特定分析目标


### <a id="5578c56ca09a5804433524047840980e"></a>未分类


- [**539**星][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) 基于虚拟化的壳的分析(静态/动态)与反混淆
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**195**星][4y] [Py] [f8left/decllvm](https://github.com/f8left/decllvm) 针对OLLVM的IDA分析插件
- [**117**星][1y] [Py] [xerub/idastuff](https://github.com/xerub/idastuff) 针对ARM处理器
- [**93**星][3m] [Py] [themadinventor/ida-xtensa](https://github.com/themadinventor/ida-xtensa) 分析Tensilica Xtensa (as seen in ESP8266)
- [**81**星][4y] [C++] [wjp/idados](https://github.com/wjp/idados) DOSBox调试器插件
    - 重复区段: [工具/调试&&动态运行&动态数据/未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**74**星][2m] [Py] [coldzer0/ida-for-delphi](https://github.com/coldzer0/ida-for-delphi) 针对Delphi的IDAPython脚本，从 Event Constructor (VCL)中获取所有函数名称
- [**59**星][2y] [Py] [isra17/nrs](https://github.com/isra17/nrs) 脱壳并分析NSIS installer打包的文件
- [**54**星][3m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) IDA MIPS静态扫描脚本，汇编审计辅助脚本
- [**53**星][4m] [C++] [troybowman/dtxmsg](https://github.com/troybowman/dtxmsg) 辅助逆向DTXConnectionServices 框架
- [**47**星][2y] [C++] [antid0tecom/aarch64_armv81extension](https://github.com/antid0tecom/aarch64_armv81extension) IDA AArch64 处理器扩展：添加对ARMv8.1 opcodes的支持
- [**47**星][8m] [C] [lab313ru/smd_ida_tools](https://github.com/lab313ru/smd_ida_tools) Sega Genesis/MegaDrive ROM文件加载器，Z80音频驱动加载器，IDA Pro调试器
- [**33**星][3y] [Py] [sam-b/windows_syscalls_dumper](https://github.com/sam-b/windows_syscalls_dumper) 转储Windows系统调用Call的 number/name，以json格式导出
- [**23**星][3y] [Py] [pfalcon/ida-xtensa2](https://github.com/pfalcon/ida-xtensa2) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266), version 2
- [**21**星][10m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) 查找标记COM组件中的函数
    - 重复区段: [工具/函数相关/重命名&&前缀&&标记](#73813456eeb8212fd45e0ea347bec349) |
- [**20**星][5y] [Py] [digitalbond/ibal](https://github.com/digitalbond/ibal) 辅助Bootrom分析
- [**17**星][2y] [C] [andywhittaker/idaproboschme7x](https://github.com/andywhittaker/idaproboschme7x) Bosch ME7x C16x反汇编辅助
- [**16**星][3y] [Py] [0xdeva/ida-cpu-risc-v](https://github.com/0xdeva/ida-cpu-risc-v) RISCV-V 反汇编器
- [**15**星][5y] [Py] [dolphin-emu/gcdsp-ida](https://github.com/dolphin-emu/gcdsp-ida) 辅助GC DSP逆向
- [**11**星][2y] [C++] [hyperiris/gekkops](https://github.com/hyperiris/gekkops) Nintendo GameCube Gekko CPU Extension plug-in for IDA Pro 5.2
- [**4**星][3y] [Py] [neogeodev/idaneogeo](https://github.com/neogeodev/idaneogeo) NeoGeo binary loader & helper for the Interactive Disassembler
- [**2**星][3m] [C] [extremlapin/glua_c_headers_for_ida](https://github.com/extremlapin/glua_c_headers_for_ida) Glua module C headers for IDA
- [**2**星][4m] [Py] [lucienmp/idapro_m68k](https://github.com/lucienmp/idapro_m68k) 扩展IDA对m68k的支持，添加gdb step-over 和类型信息支持
- [**0**星][7m] [C] [0xd0cf11e/idcscripts](https://github.com/0xd0cf11e/idcscripts) idc脚本
    - [emotet-decode](https://github.com/0xd0cf11e/idcscripts/blob/master/emotet/emotet-decode.idc) 解码emotet
- [**0**星][1m] [C++] [marakew/emuppc](https://github.com/marakew/emuppc) PowerPC模拟器，脱壳某些 PowerPC 二进制文件


### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**363**星][8m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) 解析Go语言编译的二进制文件中的GoLang类型信息
- [**285**星][20d] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) 辅助Go逆向


### <a id="4c158ccc5aee04383755851844fdd137"></a>Windows驱动


- [**303**星][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**216**星][12m] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) 辅助逆向Windows内核驱动
- [**73**星][4y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA插件，将Windows设备IO控制码解码成为DeviceType, FunctionCode, AccessType, MethodType.
- [**23**星][1y] [C] [ioactive/kmdf_re](https://github.com/ioactive/kmdf_re) 辅助逆向KMDF驱动


### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4


- [**68**星][2m] [C] [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel) A collection of IDA loaders for various game console ELF's. (PS3, PSVita, WiiU)
- [**55**星][7y] [C++] [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) IDA scripts and plugins for PS3
- [**44**星][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) 辅助PS4用户模式ELF逆向
    - 重复区段: [工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**29**星][5y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - 重复区段: [工具/导入导出&与其他工具交互/未分类](#8ad723b704b044e664970b11ce103c09) |


### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**205**星][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) WebAssembly的加载器和解析器
- [**158**星][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [工具/Android](#66052f824f5054aa0f70785a2389a478) |[工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**155**星][2y] [Py] [crytic/ida-evm](https://github.com/crytic/ida-evm) 以太坊虚拟机的Processor模块
- [**138**星][25d] [Py] [argp/iboot64helper](https://github.com/argp/iboot64helper) IDAPython loader to help with AArch64 iBoot, iBEC, and SecureROM reverse engineering
- [**127**星][2y] [C] [gsmk/hexagon](https://github.com/gsmk/hexagon) IDA processor module for the hexagon (QDSP6) processor
- [**106**星][1y] [pgarba/switchidaproloader](https://github.com/pgarba/switchidaproloader) Loader for IDA Pro to support the Nintendo Switch NRO binaries
- [**72**星][2y] [Py] [embedi/meloader](https://github.com/embedi/meloader) 加载英特尔管理引擎固件
- [**54**星][5m] [C++] [mefistotelis/ida-pro-loadmap](https://github.com/mefistotelis/ida-pro-loadmap) Plugin for IDA Pro disassembler which allows loading .map files.
- [**37**星][11m] [C++] [patois/nesldr](https://github.com/patois/nesldr) Nintendo Entertainment System (NES) ROM loader module for IDA Pro
- [**35**星][1y] [Py] [bnbdr/ida-bpf-processor](https://github.com/bnbdr/ida-bpf-processor) BPF Processor for IDA Python
- [**32**星][5y] [Py] [0xebfe/3dsx-ida-pro-loader](https://github.com/0xebfe/3dsx-ida-pro-loader) IDA PRO Loader for 3DSX files
- [**32**星][1y] [C++] [teammolecule/toshiba-mep-idp](https://github.com/TeamMolecule/toshiba-mep-idp) IDA Pro module for Toshiba MeP processors
- [**28**星][4y] [C] [gdbinit/teloader](https://github.com/gdbinit/teloader) A TE executable format loader for IDA
- [**27**星][3y] [Py] [w4kfu/ida_loader](https://github.com/w4kfu/ida_loader) loader module 收集
- [**25**星][2m] [Py] [ghassani/mclf-ida-loader](https://github.com/ghassani/mclf-ida-loader) An IDA file loader for Mobicore trustlet and driver binaries
- [**23**星][1y] [C++] [balika011/belf](https://github.com/balika011/belf) Balika011's PlayStation 4 ELF loader for IDA Pro 7.0/7.1
- [**23**星][6y] [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) IDA loader plugin for Qualcomm Bootloader Stages
- [**20**星][3y] [C++] [patois/ndsldr](https://github.com/patois/ndsldr) Nintendo DS ROM loader module for IDA Pro
- [**18**星][8y] [Py] [rpw/flsloader](https://github.com/rpw/flsloader) IDA Pro loader module for Infineon/Intel-based iPhone baseband firmwares
- [**17**星][8m] [C++] [gocha/ida-snes-ldr](https://github.com/gocha/ida-snes-ldr) SNES ROM Cartridge File Loader for IDA (Interactive Disassembler) 6.x
- [**16**星][10m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) 针对已编译Yara规则文件的Loader&&Processor
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**16**星][8m] [C++] [gocha/ida-65816-module](https://github.com/gocha/ida-65816-module) SNES 65816 processor plugin for IDA (Interactive Disassembler) 6.x
- [**16**星][12m] [Py] [lcq2/riscv-ida](https://github.com/lcq2/riscv-ida) RISC-V ISA处理器模块
- [**16**星][1y] [Py] [ptresearch/nios2](https://github.com/ptresearch/nios2) IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture
- [**13**星][2y] [Py] [patois/necromancer](https://github.com/patois/necromancer) IDA Pro V850 Processor Module Extension
- [**13**星][1y] [Py] [rolfrolles/hiddenbeeloader](https://github.com/rolfrolles/hiddenbeeloader) IDA loader module for Hidden Bee's custom executable file format
- [**10**星][4y] [C++] [areidz/nds_loader](https://github.com/areidz/nds_loader) Nintendo DS loader module for IDA Pro 6.1
- [**10**星][6y] [Py] [cycad/mbn_loader](https://github.com/cycad/mbn_loader) IDA Pro Loader Plugin for Samsung Galaxy S4 ROMs
- [**7**星][1y] [C++] [fail0verflow/rl78-ida-proc](https://github.com/fail0verflow/rl78-ida-proc) Renesas RL78 processor module for IDA
- [**5**星][8m] [C++] [gocha/ida-spc700-module](https://github.com/gocha/ida-spc700-module) SNES SPC700 processor plugin for IDA (Interactive Disassembler)
- [**3**星][8m] [C++] [gocha/ida-snes_spc-ldr](https://github.com/gocha/ida-snes_spc-ldr) SNES-SPC700 Sound File Loader for IDA (Interactive Disassembler)
- [**2**星][2m] [C] [cisco-talos/ida_tilegx](https://github.com/cisco-talos/ida_tilegx) This is an IDA processor module for the Tile-GX processor architecture


### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB


- [**87**星][3m] [C++] [mixaill/fakepdb](https://github.com/mixaill/fakepdb) 通过IDA数据库生成PDB文件
- [**38**星][1y] [Py] [ax330d/ida_pdb_loader](https://github.com/ax330d/ida_pdb_loader) IDA PDB Loader
- [**14**星][1y] [CMake] [gdataadvancedanalytics/bindifflib](https://github.com/gdataadvancedanalytics/bindifflib) Automated library compilation and PDB annotation with CMake and IDA Pro
- [**2**星][5m] [Py] [clarkb7/annotate_lineinfo](https://github.com/clarkb7/annotate_lineinfo) Annotate IDA with source and line number information from a PDB


### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF


- [**33**星][1y] [Py] [kasperskylab/actionscript3](https://github.com/kasperskylab/actionscript3) SWF Loader、ActionScript3 Processor和 IDA 调试辅助插件
- [**27**星][4y] [C++] [nihilus/ida-pro-swf](https://github.com/nihilus/ida-pro-swf) 处理SWF文件


### <a id="841d605300beba45c3be131988514a03"></a>特定样本家族


- [**9**星][2y] [Py] [d00rt/easy_way_nymaim](https://github.com/d00rt/easy_way_nymaim) IDA脚本, 用于去除恶意代码nymaim的混淆,创建干净的idb
- [**8**星][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) Nymaim 家族样本反混淆插件
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**4**星][2y] [Py] [immortalp0ny/fyvmdisassembler](https://github.com/immortalp0ny/fyvmdisassembler) 对 FinSpy VM进行反虚拟化/反汇编的IDAPython脚本
- [**4**星][7m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) 解密 GandCrab v5.1-5.3 中的字符串
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF


- [**130**星][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) DEFCON 25 某Talk用到的 反汇编器和 IDA 模块




***


## <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython本身


### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>未分类


- [**707**星][4d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython源码
- [**365**星][1m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython的高级抽象
- [**249**星][2y] [Py] [intezer/docker-ida](https://github.com/intezer/docker-ida) 在Docker容器中执行IDA, 以自动化/可扩展/分布式的方式执行IDAPython脚本
- [**79**星][4y] [idapython/bin](https://github.com/idapython/bin) IDAPython binaries
- [**65**星][2y] [Py] [alexander-hanel/idapython6to7](https://github.com/alexander-hanel/idapython6to7) None
- [**43**星][1y] [Py] [nirizr/pytest-idapro](https://github.com/nirizr/pytest-idapro) 辅助对IDAPython脚本进行单元测试
- [**28**星][2y] [Py] [kerrigan29a/idapython_virtualenv](https://github.com/kerrigan29a/idapython_virtualenv) 在IDAPython中启用Virtualenv或Conda，使可以有多个虚拟环境
- [**23**星][3y] [Py] [devttys0/idascript](https://github.com/devttys0/idascript) IDA的Wrapper，在命令行中自动对目标文件执行IDA脚本


### <a id="c42137cf98d6042372b1fd43c3635135"></a>cheatsheets


- [**232**星][1m] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




***


## <a id="846eebe73bef533041d74fc711cafb43"></a>指令参考&文档


- [**494**星][11m] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) 指令参考插件.
- [**441**星][3m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**242**星][2y] [Py] [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight) 用于高亮和解码 ARM 系统指令
- [**104**星][22d] [Py] [neatmonster/amie](https://github.com/neatmonster/amie) 针对ARM架构的`FRIEND`插件, 文档增强
- [**45**星][8y] [Py] [zynamics/msdn-plugin-ida](https://github.com/zynamics/msdn-plugin-ida) Imports MSDN documentation into IDA Pro
- [**25**星][3y] [AutoIt] [yaseralnajjar/ida-msdn-helper](https://github.com/yaseralnajjar/IDA-MSDN-helper) IDA Pro MSDN Helper


***


## <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>辅助脚本编写


### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>未分类


- [**383**星][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) 基于Unicorn引擎的代码模拟插件
    - 重复区段: [工具/模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**271**星][4d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [工具/模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**135**星][5d] [Py] [arizvisa/ida-minsc](https://github.com/arizvisa/ida-minsc) IDA-minsc is a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler. This plugin groups the different aspects of the IDAPython API into a simpler format which allows a reverse engineer to script aspects of their work with very little investment. Smash that "Star" button if you like this.
- [**97**星][20d] [Py] [patois/idapyhelper](https://github.com/patois/idapyhelper) IDAPython脚本编写辅助
- [**74**星][3m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) IDA“最近脚本/执行脚本”的进化版
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**42**星][5m] [C++] [0xeb/ida-climacros](https://github.com/0xeb/ida-climacros) 在IDA命令行接口中定义和使用静态/动态的宏
- [**32**星][2y] [CMake] [zyantific/ida-cmake](https://github.com/zyantific/ida-cmake) 使用CMake编译C++编写的IDA脚本
- [**22**星][1y] [Py] [nirizr/idasix](https://github.com/nirizr/idasix) IDAPython兼容库。创建平滑的IDA开发流程，使相同代码可应用于多个IDA/IDAPython版本
- [**4**星][6m] [inndy/idapython-cheatsheet](https://github.com/inndy/idapython-cheatsheet) scripting IDA like a Pro


### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt


- [**25**星][11m] [techbliss/ida_pro_ultimate_qt_build_guide](https://github.com/techbliss/ida_pro_ultimate_qt_build_guide) Ida Pro Ultimate Qt Build Guide
- [**13**星][2m] [Py] [tmr232/cute](https://github.com/tmr232/cute) 在IDAPython中兼容QT4/QT5
- [**9**星][3y] [Py] [techbliss/ida_pro_screen_recorder](https://github.com/techbliss/ida_pro_screen_recorder) PyQt plugin for Ida Pro for Screen recording.


### <a id="1721c09501e4defed9eaa78b8d708361"></a>控制台&&窗口界面


- [**260**星][14d] [Py] [eset/ipyida](https://github.com/eset/ipyida) 集成IPython控制台
- [**231**星][2y] [Jupyter Notebook] [james91b/ida_ipython](https://github.com/james91b/ida_ipython) 嵌入IPython内核，集成IPython
- [**175**星][3m] [Py] [techbliss/python_editor](https://github.com/techbliss/python_editor) Python脚本编辑窗口


### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>插件模板


- [**5**星][2y] [C++] [patois/ida_vs2017](https://github.com/patois/ida_vs2017) IDA 7.x VS 2017 项目模板
- [**4**星][5y] [JS] [nihilus/ida-pro-plugin-wizard-for-vs2013](https://github.com/nihilus/ida-pro-plugin-wizard-for-vs2013) None


### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>其他语言


- [**22**星][3y] [Java] [cblichmann/idajava](https://github.com/cblichmann/idajava) Java integration for Hex-Rays IDA Pro
- [**8**星][3y] [C++] [nlitsme/idaperl](https://github.com/nlitsme/idaperl) 在IDA中使用Perl编写脚本




***


## <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>古老的


- [**163**星][4y] [Py] [osirislab/fentanyl](https://github.com/osirislab/Fentanyl) 简化打补丁
- [**127**星][6y] [C++] [crowdstrike/crowddetox](https://github.com/crowdstrike/crowddetox) None
- [**94**星][5y] [Py] [nihilus/ida-idc-scripts](https://github.com/nihilus/ida-idc-scripts) 多个IDC脚本收集
- [**83**星][6y] [Py] [einstein-/hexrays-python](https://github.com/einstein-/hexrays-python) Python bindings for the Hexrays Decompiler
- [**76**星][5y] [PHP] [v0s/plus22](https://github.com/v0s/plus22) Tool to analyze 64-bit binaries with 32-bit Hex-Rays Decompiler
- [**63**星][5y] [C] [nihilus/idastealth](https://github.com/nihilus/idastealth) None
- [**40**星][6y] [C++] [wirepair/idapinlogger](https://github.com/wirepair/idapinlogger) Logs instruction hits to a file which can be fed into IDA Pro to highlight which instructions were called.
- [**39**星][10y] [izsh/ida-python-scripts](https://github.com/izsh/ida-python-scripts) IDA Python Scripts
- [**39**星][8y] [Py] [zynamics/bincrowd-plugin-ida](https://github.com/zynamics/bincrowd-plugin-ida) BinCrowd Plugin for IDA Pro
- [**35**星][8y] [Py] [zynamics/ida2sql-plugin-ida](https://github.com/zynamics/ida2sql-plugin-ida) None
- [**27**星][4y] [C++] [luorui110120/idaplugins](https://github.com/luorui110120/idaplugins) 一堆IDA插件，无文档
- [**21**星][10y] [C++] [sporst/ida-pro-plugins](https://github.com/sporst/ida-pro-plugins) Collection of IDA Pro plugins I wrote over the years
- [**18**星][10y] [Py] [binrapt/ida](https://github.com/binrapt/ida) Python script which extracts procedures from IDA Win32 LST files and converts them to correctly dynamically linked compilable Visual C++ inline assembly.
- [**15**星][7y] [Py] [nihilus/optimice](https://github.com/nihilus/optimice) None
- [**10**星][10y] [jeads-sec/etherannotate_ida](https://github.com/jeads-sec/etherannotate_ida) EtherAnnotate IDA Pro Plugin - Parse EtherAnnotate trace files and markup IDA disassemblies with runtime values
- [**6**星][10y] [C] [jeads-sec/etherannotate_xen](https://github.com/jeads-sec/etherannotate_xen) EtherAnnotate Xen Ether Modification - Adds a feature to Ether that pulls register values and potential string values at each instruction during an instruction trace.


***


## <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>调试&&动态运行&动态数据


### <a id="2944dda5289f494e5e636089db0d6a6a"></a>未分类


- [**390**星][11m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [工具/模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**184**星][5y] [C++] [nihilus/scyllahide](https://github.com/nihilus/scyllahide) 用户模式反-反调试
- [**105**星][1m] [Py] [danielplohmann/apiscout](https://github.com/danielplohmann/apiscout) 简化导入API恢复。可以从内存中恢复API信息。包含命令行版本和IDA插件。可以处理PE头被抹掉等ImpRec/ImpRec无法处理的情况。
- [**81**星][4y] [C++] [wjp/idados](https://github.com/wjp/idados) DOSBox调试器插件
    - 重复区段: [工具/针对特定分析目标/未分类](#5578c56ca09a5804433524047840980e) |
- [**56**星][7y] [Py] [cr4sh/ida-vmware-gdb](https://github.com/cr4sh/ida-vmware-gdb) 辅助Windows内核调试
- [**42**星][5y] [Py] [nihilus/idasimulator](https://github.com/nihilus/idasimulator) 扩展IDA的条件断点支持，在被调试进行中使用Python代码替换复杂的执行代码
- [**38**星][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) 辅助Android调试的IDAPython脚本
    - 重复区段: [工具/Android](#66052f824f5054aa0f70785a2389a478) |
- [**22**星][5y] [Py] [techbliss/scylladumper](https://github.com/techbliss/scylladumper) Ida Plugin to Use the Awsome Scylla plugin
- [**14**星][5y] [Py] [techbliss/free_the_debuggers](https://github.com/techbliss/free_the_debuggers) 自动加载并执行调试器插件？？
- [**0**星][2y] [Py] [benh11235/ida-windbglue](https://github.com/benh11235/ida-windbglue) 与远程WinDBG调试服务器进行连接的"胶水"脚本


### <a id="0fbd352f703b507853c610a664f024d1"></a>DBI数据


- [**929**星][11m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) 从DBI中收集代码覆盖情况，在IDA/Binja中映射、浏览、查看
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**133**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [工具/导入导出&与其他工具交互/IntelPin](#dd0332da5a1482df414658250e6357f8) |[工具/漏洞/未分类](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**129**星][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) 在Frida Client和IDA之间建立连接，将运行时信息直接导入IDA，并可直接在IDA中控制Frida
    - 重复区段: [工具/导入导出&与其他工具交互/Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**121**星][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) 使用Pin收集动态运行数据, 导入到IDA中查看
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**星][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) 使用Pin收集数据，导入到IDA中查看
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**88**星][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) 使用Pin收集运行数据并在IDA中显示
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**79**星][3y] [Py] [davidkorczynski/repeconstruct](https://github.com/davidkorczynski/repeconstruct) 自动脱壳并重建二进制文件
- [**51**星][10m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) 动态数据解析: 在IDA中控制DyRIO执行程序的指定部分, 记录执行过程后传回数据到IDA
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**星][8m] [C++] [secrary/findloop](https://github.com/secrary/findloop) 使用DyRIO查找执行次数过多的代码块
- [**15**星][12m] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) PinTool收集。收集数据可导入到IDA中
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 


### <a id="b31acf6c84a9506066d497af4e702bf5"></a>调试数据


- [**595**星][2m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) 利用IDA调试获取的信息，自动创建C++的虚表
    - 重复区段: [工具/结构体&&类的检测&&创建&&恢复/C++类&&虚表](#4900b1626f10791748b20630af6d6123) |
        <details>
        <summary>查看详情</summary>


        ## 静态部分: 
        - 检测非直接调用
        - 利用条件断点, Hook非直接调用的值赋值过程
        
        ## 动态 部分
        - 创建虚表结构
        - 重命名函数和虚表地址
        - 给反汇编非直接调用添加结构偏移
        - 给非直接调用到虚表之间添加交叉引用
        
        ## 使用
        - File -> Script File -> Main.py(设置断点) -> IDA调试器执行
        </details>


- [**383**星][4m] [Py] [ynvb/die](https://github.com/ynvb/die) 使用IDA调试器收集动态运行信息, 辅助静态分析
- [**378**星][4y] [Py] [deresz/funcap](https://github.com/deresz/funcap) 使用IDA调试时记录动态信息, 辅助静态分析
- [**103**星][3y] [Py] [c0demap/codemap](https://github.com/c0demap/codemap) Hook IDA，调试命中断点时将寄存器/内存信息保存到数据库，在web浏览器中查看
    - [IDA插件](https://github.com/c0demap/codemap/blob/master/idapythonrc.py) 
    - [Web服务器](https://github.com/c0demap/codemap/tree/master/codemap/server) 




***


## <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>反编译器&&AST


- [**1661**星][6m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman反编译器，支持x86, AMD64, ARM。有独立的GUI工具、命令行工具、IDA/Radare2/x64dbg插件，也可以作为库使用
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1317**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**465**星][4y] [Py] [einstein-/decompiler](https://github.com/EiNSTeiN-/decompiler) 多后端的反编译器, 支持IDA和Capstone.
- [**400**星][2m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) retdec 的 IDA 插件
- [**291**星][5y] [C++] [smartdec/smartdec](https://github.com/smartdec/smartdec) 反编译器, 带IDA插件(进阶版为: snowman)
    - [IDA插件](https://github.com/smartdec/smartdec/tree/master/src/ida-plugin) 
    - [nocode](https://github.com/smartdec/smartdec/tree/master/src/nocode) 命令行反编译器
    - [smartdec](https://github.com/smartdec/smartdec/tree/master/src/smartdec) 带GUI界面的反编译器
    - [nc](https://github.com/smartdec/smartdec/tree/master/src/nc) 反编译器的核心代码
- [**286**星][5y] [Py] [aaronportnoy/toolbag](https://github.com/aaronportnoy/toolbag) 反编译强化插件
- [**225**星][6m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**167**星][1y] [Py] [tintinweb/ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile) 将多个文件及其import用附加注释（外部参照，堆栈变量大小）反编译到pseudocode.c文件
- [**149**星][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) 反编译输出增强: 使用Python Clang解析标准的IDA反编译结果
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**103**星][7m] [Py] [sibears/hrast](https://github.com/sibears/hrast) 演示如何修改AST(抽象语法树)
- [**89**星][5m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) 反编译函数CTree可视化
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**41**星][24d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) IDA反编译器脚本，辅助审计对于memcpy() 和memmove()函数的调用
    - 重复区段: [工具/漏洞/未分类](#385d6777d0747e79cccab0a19fa90e7e) |
- [**23**星][1y] [C++] [dougallj/dj_ida_plugins](https://github.com/dougallj/dj_ida_plugins) 向Hex-Rays反编译器添加VMX intrinsics


***


## <a id="7199e8787c0de5b428f50263f965fda7"></a>反混淆


- [**1351**星][1m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**539**星][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) 基于虚拟化的壳的分析(静态/动态)与反混淆
    - 重复区段: [工具/针对特定分析目标/未分类](#5578c56ca09a5804433524047840980e) |
- [**290**星][3m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [工具/Microcode](#7a2977533ccdac70ee6e58a7853b756b) |
- [**202**星][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) 移除死代码(dead code), 基于Unicorn引擎
    - 重复区段: [工具/模拟器集成](#b38dab81610be087bd5bc7785269b8cc) |
- [**47**星][2y] [Py] [riscure/drop-ida-plugin](https://github.com/riscure/drop-ida-plugin) Experimental opaque predicate detection for IDA Pro
- [**22**星][3m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - 重复区段: [工具/污点分析&&符号执行](#34ac84853604a7741c61670f2a075d20) |
- [**8**星][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) Nymaim 家族样本反混淆插件
    - 重复区段: [工具/针对特定分析目标/特定样本家族](#841d605300beba45c3be131988514a03) |


***


## <a id="fcf75a0881617d1f684bc8b359c684d7"></a>效率&&导航&&快速访问&&图形&&图像&&可视化 


### <a id="c5b120e1779b928d860ad64ff8d23264"></a>其他


- [**1317**星][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) 反编译插件, 多功能
    - 重复区段: [工具/反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>查看详情</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**441**星][3m] [C++] [alexhude/friend](https://github.com/alexhude/friend) 反汇编显示增强, 文档增强插件
    - 重复区段: [工具/指令参考&文档](#846eebe73bef533041d74fc711cafb43) |
- [**362**星][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[工具/漏洞/未分类](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**327**星][2m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) 交互式反汇编工具, 有与IDAPython兼容的插件API
- [**225**星][6m] [Py] [patois/dsync](https://github.com/patois/dsync) 反汇编和反编译窗口同步插件
    - 重复区段: [工具/反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**183**星][22d] [Py] [danigargu/dereferencing](https://github.com/danigargu/dereferencing) 调试时寄存器和栈显示增强
- [**130**星][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) 扩展IDA的字符串导航功能
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
- [**98**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[工具/函数相关/导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc) |
- [**80**星][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) 解析函数名称，按命名空间分组，将分组结果以树的形式展示
    - 重复区段: [工具/函数相关/导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc) |
- [**74**星][3m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) IDA“最近脚本/执行脚本”的进化版
    - 重复区段: [工具/辅助脚本编写/未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**48**星][2m] [C++] [jinmo/ifred](https://github.com/jinmo/ifred) IDA command palette & more (Ctrl+Shift+P, Ctrl+P)
- [**40**星][4m] [Py] [tmr232/brutal-ida](https://github.com/tmr232/brutal-ida) 在IDA 7.3中禁用Undo/Redo
- [**23**星][6y] [C++] [cr4sh/ida-ubigraph](https://github.com/cr4sh/ida-ubigraph) IDA Pro plug-in and tools for displaying 3D graphs of procedures using UbiGraph
- [**17**星][2y] [Py] [tmr232/graphgrabber](https://github.com/tmr232/graphgrabber) 获取IDA图的全分辨率图像
- [**5**星][2y] [Py] [handsomematt/ida_func_ptr](https://github.com/handsomematt/ida_func_ptr) 右键菜单中快速拷贝函数指针定义


### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>显示增强


- [**200**星][1m] [Py] [patois/idacyber](https://github.com/patois/idacyber) 交互式数据可视化插件
- [**149**星][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) 反编译输出增强: 使用Python Clang解析标准的IDA反编译结果
    - 重复区段: [工具/反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**104**星][2y] [Py] [danigargu/idatropy](https://github.com/danigargu/idatropy) 使用idapython和matplotlib的功能生成熵和直方图的图表
- [**89**星][5m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) 反编译函数CTree可视化
    - 重复区段: [工具/反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**47**星][1m] [Py] [patois/xray](https://github.com/patois/xray) 根据正则表达式对IDA反编译输出的特定内容进行高亮显示
- [**20**星][3m] [C++] [revspbird/hightlight](https://github.com/revspbird/hightlight) 反编译窗口中代码块和括号高亮
- [**5**星][3y] [Py] [oct0xor/ida_pro_graph_styling](https://github.com/oct0xor/ida_pro_graph_styling) call/jump指令高亮显示
- [**5**星][2y] [C] [teppay/ida](https://github.com/teppay/ida) 指令高亮，黑色主题
- [**4**星][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) 在IDA调试器中高亮函数的返回地址
    - 重复区段: [工具/函数相关/未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |


### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>图形&&图像


- [**2562**星][4m] [Java] [google/binnavi](https://github.com/google/binnavi) 二进制分析IDE, 对反汇编代码的控制流程图和调用图进行探查/导航/编辑/注释.(IDA插件的作用是导出反汇编)
- [**231**星][2y] [C++] [fireeye/simplifygraph](https://github.com/fireeye/simplifygraph) 复杂graphs的简化
- [**39**星][8m] [Py] [rr-/ida-images](https://github.com/rr-/ida-images) 图像预览插件，辅助查找图像解码函数（运行复杂代码，查看内存中是否存在图像）


### <a id="8f9468e9ab26128567f4be87ead108d7"></a>搜索


- [**149**星][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) 模糊搜索: 命令/函数/结构体
    - 重复区段: [工具/函数相关/导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc) |
- [**64**星][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) 搜索工具
- [**23**星][4m] [Py] [alexander-hanel/hansel](https://github.com/alexander-hanel/hansel) IDA搜索插件




***


## <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**223**星][2y] [Py] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Android逆向脚本收集
- [**158**星][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[工具/针对特定分析目标/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**115**星][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) 基于IDA python的Android DEX内存dump工具
- [**79**星][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
- [**39**星][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
- [**38**星][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) 辅助Android调试的IDAPython脚本
    - 重复区段: [工具/调试&&动态运行&动态数据/未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**16**星][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro


***


## <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


### <a id="8530752bacfb388f3726555dc121cb1a"></a>未分类


- [**173**星][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) Duo 实验室使用的IDAPython 脚本收集
    - 重复区段: [工具/固件&&嵌入式设备](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**167**星][8y] [Py] [zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) 辅助Objective-C二进制文件的分析
- [**19**星][2y] [aozhimin/ios-monitor-resources](https://github.com/aozhimin/ios-monitor-resources) 对各厂商的 iOS SDK 性能监控方案的整理和收集后的资源
- [**17**星][9y] [C++] [alexander-pick/patchdiff2_ida6](https://github.com/alexander-pick/patchdiff2_ida6) patched up patchdiff2 to compile and work with IDA 6 on OSX
- [**14**星][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA签名文件，iPhone基带逆向
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/未分类](#cf04b98ea9da0056c055e2050da980c1) |


### <a id="82d0fa2d6934ce29794a651513934384"></a>内核缓存


- [**168**星][12m] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) 使用IDA Pro重建iOS内核缓存的C++类
    - 重复区段: [工具/结构体&&类的检测&&创建&&恢复/未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**137**星][8y] [stefanesser/ida-ios-toolkit](https://github.com/stefanesser/ida-ios-toolkit) 辅助处理iOS kernelcache的IDAPython收集
- [**50**星][1y] [Py] [synacktiv-contrib/kernelcache-laundering](https://github.com/Synacktiv-contrib/kernelcache-laundering) load iOS12 kernelcaches and PAC code in IDA


### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O


- [**47**星][6m] [C] [gdbinit/extractmacho](https://github.com/gdbinit/extractmacho) IDA plugin to extract Mach-O binaries located in the disassembly or data
- [**18**星][3y] [C] [cocoahuke/iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) This tool will help to fix the Mach-O header of iOS kernel which dump from the memory. So that IDA or function symbol-related tools can loaded function symbols of ios kernel correctly
- [**17**星][8y] [C] [gdbinit/machoplugin](https://github.com/gdbinit/machoplugin) IDA plugin to Display Mach-O headers


### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift


- [**17**星][3y] [Py] [tylerha97/swiftdemang](https://github.com/0xtyh/swiftdemang) Demangle Swift
- [**17**星][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) 对Swift函数名进行demangle
    - 重复区段: [工具/函数相关/demangle](#cadae88b91a57345d266c68383eb05c5) |




***


## <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF


- [**518**星][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) 给ELF文件打补丁(命令行+IDA插件)(可编写Python回调,C函数替换等)
    - 重复区段: [工具/补丁&&Patch](#7d557bc3d677d206ef6c5a35ca8b3a14) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**202**星][5y] [C] [snare/ida-efiutils](https://github.com/snare/ida-efiutils) 辅助ELF逆向
- [**158**星][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - 重复区段: [工具/Android](#66052f824f5054aa0f70785a2389a478) |[工具/针对特定分析目标/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**125**星][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [工具/导入导出&与其他工具交互/Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[工具/函数相关/未分类](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**90**星][2y] [C++] [gdbinit/efiswissknife](https://github.com/gdbinit/efiswissknife) 辅助 (U)EFI reversing 逆向
- [**83**星][2m] [Py] [yeggor/uefi_retool](https://github.com/yeggor/uefi_retool) 在UEFI固件和UEFI模块分析中查找专有协议的工具
- [**44**星][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) 辅助PS4用户模式ELF逆向
    - 重复区段: [工具/针对特定分析目标/PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**44**星][4y] [Py] [danse-macabre/ida-efitools](https://github.com/danse-macabre/ida-efitools) 辅助逆向ELF文件
- [**43**星][4y] [Py] [strazzere/idant-wanna](https://github.com/strazzere/idant-wanna) ELF header abuse


***


## <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**290**星][3m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) 利用Hex-Rays microcode API破解编译器级别的混淆
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**186**星][4m] [C++] [chrisps/hexext](https://github.com/chrisps/Hexext) 通过操作microcode, 优化反编译器的数据
- [**60**星][4m] [Py] [patois/genmc](https://github.com/patois/genmc) 显示Hex-Rays 反编译器的Microcode，辅助开发Microcode插件
- [**43**星][1m] [Py] [idapython/pyhexraysdeob](https://github.com/idapython/pyhexraysdeob) 工具 RolfRolles/HexRaysDeob 的Python版本
- [**19**星][8m] [Py] [neatmonster/mcexplorer](https://github.com/neatmonster/mcexplorer) 工具 RolfRolles/HexRaysDeob 的 Python 版本


***


## <a id="b38dab81610be087bd5bc7785269b8cc"></a>模拟器集成


- [**482**星][12m] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) 基于Unicorn的模拟器插件
- [**390**星][11m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) 用Unicorn引擎做后端的调试插件
    - 重复区段: [工具/调试&&动态运行&动态数据/未分类](#2944dda5289f494e5e636089db0d6a6a) |
- [**383**星][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) 基于Unicorn引擎的代码模拟插件
    - 重复区段: [工具/辅助脚本编写/未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**271**星][4d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) 结合Unicorn引擎, 简化模拟脚本的编写
    - 重复区段: [工具/辅助脚本编写/未分类](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**202**星][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) 移除死代码(dead code), 基于Unicorn引擎
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |
- [**124**星][2y] [Py] [codypierce/pyemu](https://github.com/codypierce/pyemu) 在IDA中使用x86模拟器


***


## <a id="c39dbae63d6a3302c4df8073b4d1cdc8"></a>新添加的




***


## <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>作为辅助&&构成其他的一环


- [**1515**星][10d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) 将x86, amd64, aarch64二进制文件转换成LLVM字节码
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**416**星][19d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) 汇编代码管理与分析平台(独立工具+IDA插件)
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/未分类](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**27**星][4y] [Scheme] [yifanlu/cgen](https://github.com/yifanlu/cgen) CGEN的Fork，增加了生成IDA IDP模块的支持
- [**23**星][2y] [Py] [tintinweb/unbox](https://github.com/tintinweb/unbox) Unbox is a convenient one-click unpack and decompiler tool that wraps existing 3rd party applications like IDA Pro, JD-Cli, Dex2Src, and others to provide a convenient archiver liker command line interfaces to unpack and decompile various types of files


***


## <a id="1ded622dca60b67288a591351de16f8b"></a>漏洞


### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>未分类


- [**489**星][6m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) 查看glibc堆, 主要用于漏洞开发
- [**376**星][2y] [Py] [1111joe1111/ida_ea](https://github.com/1111joe1111/ida_ea) 用于辅助漏洞开发和逆向
- [**362**星][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**137**星][6m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) 辅助漏洞研究
- [**133**星][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) 多功能, 带界面,辅助静态分析、漏洞挖掘、动态追踪(Pin)、导入导出等
    - 重复区段: [工具/导入导出&与其他工具交互/IntelPin](#dd0332da5a1482df414658250e6357f8) |[工具/调试&&动态运行&动态数据/DBI数据](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**41**星][24d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) IDA反编译器脚本，辅助审计对于memcpy() 和memmove()函数的调用
    - 重复区段: [工具/反编译器&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**32**星][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) IDAPython script for quick vulnerability analysis


### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP


- [**53**星][3y] [Py] [patois/drgadget](https://github.com/patois/drgadget) 开发和分析ROP链
- [**19**星][1y] [Py] [lucasg/idarop](https://github.com/lucasg/idarop) 列举并存储ROP gadgets




***


## <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>补丁&&Patch


- [**713**星][11m] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) 汇编/补丁插件, 支持多架构, 基于Keystone引擎
- [**518**星][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) 给ELF文件打补丁(命令行+IDA插件)(可编写Python回调,C函数替换等)
    - 重复区段: [工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**87**星][5y] [Py] [iphelix/ida-patcher](https://github.com/iphelix/ida-patcher) 二进制文件和内存补丁
- [**42**星][3y] [C++] [mrexodia/idapatch](https://github.com/mrexodia/idapatch) IDA plugin to patch IDA Pro in memory.
- [**30**星][2m] [Py] [scottmudge/debugautopatch](https://github.com/scottmudge/debugautopatch) Patching system improvement plugin for IDA.
- [**16**星][8y] [C++] [jkoppel/reprogram](https://github.com/jkoppel/reprogram) Patch binaries at load-time
- [**0**星][7m] [Py] [tkmru/genpatch](https://github.com/tkmru/genpatch) 生成用于打补丁的Python脚本


***


## <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>其他


- [**120**星][2y] [Shell] [feicong/ida_for_mac_green](https://github.com/feicong/ida_for_mac_green) IDAPro 绿化增强版 （macOS）
- [**28**星][4m] [angelkitty/ida7.0](https://github.com/angelkitty/ida7.0) 
- [**16**星][2y] [jas502n/ida7.0-pro](https://github.com/jas502n/ida7.0-pro) IDA7.0 下载


***


## <a id="90bf5d31a3897400ac07e15545d4be02"></a>函数相关


### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>未分类


- [**125**星][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) 将IDA Pro和Radare2识别的符号（目前仅函数）导出到ELF符号表
    - 重复区段: [工具/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[工具/导入导出&与其他工具交互/Radare2](#21ed198ae5a974877d7a635a4b039ae3) |
- [**11**星][2y] [C++] [fireundubh/ida7-functionstringassociate](https://github.com/fireundubh/ida7-functionstringassociate) FunctionStringAssociate plugin by sirmabus, ported to IDA 7
- [**4**星][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) 在IDA调试器中高亮函数的返回地址
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /显示增强](#03fac5b3abdbd56974894a261ce4e25f) |
- [**2**星][4m] [Py] [farzonl/idapropluginlab3](https://github.com/farzonl/idapropluginlab3) 通过静态分析使用的函数，描述恶意代码的行为


### <a id="73813456eeb8212fd45e0ea347bec349"></a>重命名&&前缀&&标记


- [**285**星][1m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) 自动化函数重命名
- [**117**星][5y] [C++] [zyantific/retypedef](https://github.com/zyantific/retypedef) 函数名称替换，可以自定义规则
- [**95**星][2y] [Py] [gaasedelen/prefix](https://github.com/gaasedelen/prefix) IDA 插件，为函数添加前缀
- [**47**星][3y] [Py] [alessandrogario/ida-function-tagger](https://github.com/alessandrogario/ida-function-tagger) 根据函数使用的导入表，对函数进行标记
- [**21**星][10m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) 查找标记COM组件中的函数
    - 重复区段: [工具/针对特定分析目标/未分类](#5578c56ca09a5804433524047840980e) |
- [**3**星][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) 对比Linux和Windows二进制文件，对Windows文件未命名的函数进行自动重命名
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/未分类](#cf04b98ea9da0056c055e2050da980c1) |


### <a id="e4616c414c24b58626f834e1be079ebc"></a>导航&&查看&&查找


- [**178**星][5m] [Py] [hasherezade/ida_ifl](https://github.com/hasherezade/ida_ifl) 交互式函数列表
- [**149**星][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) 模糊搜索: 命令/函数/结构体
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /搜索](#8f9468e9ab26128567f4be87ead108d7) |
- [**98**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [工具/字符串](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**80**星][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) 解析函数名称，按命名空间分组，将分组结果以树的形式展示
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**33**星][3y] [Py] [darx0r/reef](https://github.com/darx0r/reef) 显示"由指定函数发起的"交叉应用。可以理解为函数内部引用的其他函数


### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle


- [**17**星][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) 对Swift函数名进行demangle
    - 重复区段: [工具/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/Swift](#1c698e298f6112a86c12881fbd8173c7) |
- [**14**星][1y] [Py] [ax330d/exports-plus](https://github.com/ax330d/exports-plus) 修复IDA不显示全部导出项以及不对导出项名称进行demangle的问题




***


## <a id="34ac84853604a7741c61670f2a075d20"></a>污点分析&&符号执行


- [**924**星][10d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) 二进制代码静态分析工具。值分析（寄存器、内存）、污点分析、类型重建和传播（propagation）、前向/后向分析
    - 重复区段: [工具/结构体&&类的检测&&创建&&恢复/未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**863**星][2y] [C++] [illera88/ponce](https://github.com/illera88/ponce) 简化污点分析+符号执行
- [**22**星][3m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |


***


## <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>字符串


- [**1351**星][1m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) 自动从恶意代码中提取反混淆后的字符串
    - 重复区段: [工具/反混淆](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**362**星][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) 若干快速访问功能, 扫描字符串格式化漏洞
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |[工具/漏洞/未分类](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>查看详情</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**178**星][11d] [Py] [joxeankoret/idamagicstrings](https://github.com/joxeankoret/idamagicstrings) 从字符串常量中提取信息
- [**130**星][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) 扩展IDA的字符串导航功能
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |
- [**98**星][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) 递归查找函数和字符串
    - 重复区段: [工具/效率&&导航&&快速访问&&图形&&图像&&可视化 /其他](#c5b120e1779b928d860ad64ff8d23264) |[工具/函数相关/导航&&查看&&查找](#e4616c414c24b58626f834e1be079ebc) |
- [**45**星][5y] [Py] [kyrus/ida-translator](https://github.com/kyrus/ida-translator) 将IDB数据库中的任意字符集转换为Unicode，然后自动调用基于网页的翻译服务（当前只有谷歌翻译）将非英文语言翻译为英文
- [**4**星][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) 在指定地址区间内搜索字符串，并将其映射为C结构体
    - 重复区段: [工具/结构体&&类的检测&&创建&&恢复/未分类](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**4**星][7m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) 解密 GandCrab v5.1-5.3 中的字符串
    - 重复区段: [工具/针对特定分析目标/特定样本家族](#841d605300beba45c3be131988514a03) |


***


## <a id="06d2caabef97cf663bd29af2b1fe270c"></a>加密解密


- [**424**星][20d] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) 使用Yara规则查找加密常量
    - 重复区段: [工具/签名(FLIRT等)&&比较(Diff)&&匹配/Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**122**星][1m] [Py] [you0708/ida](https://github.com/you0708/ida) 查找加密常量
    - [IDA主题](https://github.com/you0708/ida/tree/master/theme) 
    - [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) IDA FindCrypt/FindCrypt2 插件的Python版本
- [**41**星][7y] [C++] [vlad902/findcrypt2-with-mmx](https://github.com/vlad902/findcrypt2-with-mmx) 对findcrypt2插件的增强，支持MMX AES指令


# <a id="35f8efcff18d0449029e9d3157ac0899"></a>TODO


- 对工具进行更细致的分类
- 为工具添加详细的中文描述，包括其内部实现原理和使用方式
- 添加非Github repo
- 补充文章
- 修改已添加文章的描述


# <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>文章


***


## <a id="4187e477ebc45d1721f045da62dbf4e8"></a>未分类


- 2019.10 [amossys] [探秘Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)
- 2019.07 [kienbigmummy] [Cách export data trong IDA](https://medium.com/p/d4c8128704f)
- 2019.05 [360_anquanke_learning] [IDAPython实战项目——DES算法识别](https://www.anquanke.com/post/id/177808/)
- 2019.05 [carbonblack] [fn_fuzzy: Fast Multiple Binary Diffing Triage with IDA](https://www.carbonblack.com/2019/05/09/fn_fuzzy-fast-multiple-binary-diffing-triage-with-ida/)
- 2019.05 [aliyun_xz] [混淆IDA F5的一个小技巧-x86](https://xz.aliyun.com/t/5062)
- 2019.03 [freebuf] [Ponce：一键即可实现符号执行（IDA插件）](https://www.freebuf.com/sectool/197708.html)
- 2019.03 [360_anquanke_learning] [为CHIP-8编写IDA processor module](https://www.anquanke.com/post/id/172217/)
- 2019.01 [pediy_new_digest] [[原创]IDA7.2安装包分析](https://bbs.pediy.com/thread-248989.htm)
- 2019.01 [pediy_new_digest] [[原创]IDA 在解析 IA64 中的 brl 指令时存在一个 Bug](https://bbs.pediy.com/thread-248983.htm)
- 2019.01 [ly0n] [Cracking with IDA (redh@wk 2.5 crackme)](https://paumunoz.tech/2019/01/05/cracking-with-ida-redhwk-2-5-crackme/)
- 2018.11 [hexblog] [IDA 7.2 – The Mac Rundown](http://www.hexblog.com/?p=1300)
- 2018.11 [pediy_new_digest] [[原创]IDA动态调试ELF](https://bbs.pediy.com/thread-247830.htm)
- 2018.10 [pediy_new_digest] [[原创] 修复 IDA Pro 7.0在macOS Mojave崩溃的问题](https://bbs.pediy.com/thread-247334.htm)
- 2018.10 [ptsecurity_blog] [Modernizing IDA Pro: how to make processor module glitches go away](http://blog.ptsecurity.com/2018/10/modernizing-ida-pro-how-to-make.html)
- 2018.10 [aliyun_xz] [IDA-minsc在Hex-Rays插件大赛中获得第二名（2）](https://xz.aliyun.com/t/2842)
- 2018.10 [aliyun_xz] [IDA-minsc在Hex-Rays插件大赛中获得第二名（1）](https://xz.aliyun.com/t/2841)
- 2018.10 [aliyun_xz] [通过两个IDAPython插件支持A12 PAC指令和iOS12 kernelcache 重定位](https://xz.aliyun.com/t/2839)
- 2018.09 [cisco_blogs] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blogs.cisco.com/security/talos/ida-minsc-wins-second-place-in-hex-rays-plugins-contest)
- 2018.09 [dustri] [IDAPython vs. r2pipe](https://dustri.org/b/idapython-vs-r2pipe.html)
- 2018.06 [pediy_new_digest] [[翻译]在IDA中使用Python Z3库来简化函数中的算术运算](https://bbs.pediy.com/thread-228688.htm)
- 2018.05 [hexblog] [IDAPython: wrappers are only wrappers](http://www.hexblog.com/?p=1219)
- 2018.05 [tradahacking] [So sánh binary bằng IDA và các công cụ bổ trợ](https://medium.com/p/651e62117695)
- 2018.04 [pediy_new_digest] [[翻译]IDAPython-Book（Alexander Hanel）](https://bbs.pediy.com/thread-225920.htm)
- 2018.03 [hexblog] [IDA on non-OS X/Retina Hi-DPI displays](http://www.hexblog.com/?p=1180)
- 2018.03 [pediy_new_digest] [[翻译]IDA v6.5 文本执行](https://bbs.pediy.com/thread-225514.htm)
- 2018.02 [pediy_new_digest] [[原创]逆向技术之熟悉IDA工具](https://bbs.pediy.com/thread-224499.htm)
- 2018.01 [pediy_new_digest] [[原创]ARM Linux下搭建IDA Pro远程调试环境](https://bbs.pediy.com/thread-224337.htm)
- 2018.01 [pediy_new_digest] [[翻译]对抗IDA Pro调试器ARM反汇编的技巧](https://bbs.pediy.com/thread-223894.htm)
- 2017.12 [youtube_OALabs] [Debugging shellcode using BlobRunner and IDA Pro](https://www.youtube.com/watch?v=q9q8dy-2Jeg)
- 2017.12 [pediy_new_digest] [[原创]IDA7.0 Mac 插件编译指南](https://bbs.pediy.com/thread-223211.htm)
- 2017.12 [pediy_new_digest] [[原创]IDA 插件- FRIEND 的安装和使用](https://bbs.pediy.com/thread-223156.htm)
- 2017.12 [youtube_BinaryAdventure] [IDAPython Tutorial with example script](https://www.youtube.com/watch?v=5ehI2wgcSGo)
- 2017.11 [youtube_OALabs] [How To Defeat Anti-VM and Anti-Debug Packers With IDA Pro](https://www.youtube.com/watch?v=WlE8abc8V-4)
- 2017.11 [pediy_new_digest] [[原创]IDAPython脚本分享 - 自动在JNI_OnLoad下断点](https://bbs.pediy.com/thread-222998.htm)
- 2017.11 [pediy_new_digest] [[求助]IDA Pro调试so，附加完毕，跳到目标so基址，但是内容都是DCB伪指令？](https://bbs.pediy.com/thread-222646.htm)
- 2017.11 [youtube_OALabs] [IDA Pro Malware Analysis Tips](https://www.youtube.com/watch?v=qCQRKLaz2nQ)
- 2017.10 [hexblog] [IDA and common Python issues](http://www.hexblog.com/?p=1132)
- 2017.10 [pediy_new_digest] [[分享]IDA + VMware 调试win7 x64](https://bbs.pediy.com/thread-221884.htm)
- 2017.06 [pediy_new_digest] [[翻译]IDA Hex-Rays反编译器使用的一些小技巧](https://bbs.pediy.com/thread-218780.htm)
- 2017.06 [qmemcpy] [IDA series, part 2: debugging a .NET executable](https://qmemcpy.io/post/ida-series-2-debugging-net)
- 2017.06 [qmemcpy] [IDA series, part 1: the Hex-Rays decompiler](https://qmemcpy.io/post/ida-series-1-hex-rays)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2017.05 [pediy_new_digest] [[原创] IDA导入Jni.h](https://bbs.pediy.com/thread-217701.htm)
- 2017.05 [oct0xor] [Advanced Ida Pro Instruction Highlighting](http://oct0xor.github.io/2017/05/03/ida_coloring/)
- 2017.05 [repret] [静态分析提高 Fuzzing 的代码覆盖率：使用 IDA 脚本枚举所有 CMP 指令及与CMP 相关的 JUMP 指令，生成反转 CMP 条件的字典，Fuzzing 时由 KFUZZ 注入。](https://repret.wordpress.com/2017/05/01/improving-coverage-guided-fuzzing-using-static-analysis/)
- 2017.04 [osandamalith] [使Windows Loader直接执行ShellCode，IDA载入文件时崩溃，而且绕过大多数杀软。](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
- 2017.04 [hexacorn] [IDA, hotpatched functions and signatures that don’t work…](http://www.hexacorn.com/blog/2017/04/07/ida-hotpatched-functions-and-signatures-that-dont-work/)
- 2017.04 [_0xec] [Remote debugging in IDA Pro by http tunnelling](https://0xec.blogspot.com/2017/04/remote-debugging-in-ida-pro-by-http.html)
- 2017.03 [pediy_new_digest] [[翻译]如何让 IDA Pro 使用我们提供的 Python 版本以及如何在 Chroot 的环境中运行 IDA Pro](https://bbs.pediy.com/thread-216643.htm)
- 2017.01 [kudelskisecurity] [SANS Holiday Hack Challenge 2016](https://research.kudelskisecurity.com/2017/01/06/sans-holiday-hack-challenge-2016/)
- 2016.12 [adelmas] [API Hooking with IDA Pro](http://adelmas.com/blog/ida_api_hooking.php)
- 2016.12 [hexacorn] [IDA, function alignment and signatures that don’t work…](http://www.hexacorn.com/blog/2016/12/27/ida-function-alignment-and-signatures-that-dont-work/)
- 2016.10 [_0x90] [Build IDA Pro KeyPatch for Fedora Linux](https://www.0x90.se/build-ida-pro-keypatch-for-fedora-linux/)
- 2016.05 [lucasg] [Do not load dll from System32 directly into IDA](http://lucasg.github.io/2016/05/30/Do-not-load-dll-from-System32-directly-into-IDA/)
- 2016.04 [hexacorn] [Creating IDT/IDS files for IDA from MS libraries with symbols](http://www.hexacorn.com/blog/2016/04/22/creating-idtids-files-for-ida-from-ms-libraries-with-symbols/)
- 2016.02 [pediy_new_digest] [[原创]翻译，IDA调试Dalvik](https://bbs.pediy.com/thread-207891.htm)
- 2016.01 [pediy_new_digest] [[原创]Android 5.0 + IDA 6.8 调试经验分享](https://bbs.pediy.com/thread-207548.htm)
- 2016.01 [insinuator] [Dynamic IDA Enrichment (aka. DIE)](https://insinuator.net/2016/01/die/)
- 2016.01 [360_anquanke_learning] [在OSX上编译非osx ida pro插件](https://www.anquanke.com/post/id/83385/)
- 2016.01 [adventuresincyberchallenges] [SANS Holiday Hack Quest 2015](https://adventuresincyberchallenges.blogspot.com/2016/01/holiday-hack-quest.html)
- 2015.12 [yifan] [CGEN for IDA Pro](http://yifan.lu/2015/12/29/cgen-for-ida-pro/)
- 2015.12 [pediy_new_digest] [调试篇---安卓arm/x86平台之IDA or GDB长驱直入](https://bbs.pediy.com/thread-206654.htm)
- 2015.12 [hexacorn] [IDAPython – making strings decompiler-friendly](http://www.hexacorn.com/blog/2015/12/21/idapython-making-strings-decompiler-friendly/)
- 2015.12 [pediy_new_digest] [[原创]IDA Pro 6.8 安装密码爆破的可行性分析](https://bbs.pediy.com/thread-206346.htm)
- 2015.11 [govolution] [Very first steps with IDA](https://govolution.wordpress.com/2015/11/06/very-first-steps-with-ida/)
- 2015.08 [pediy_new_digest] [[原创]一步步搭建ida pro动态调试SO环境。](https://bbs.pediy.com/thread-203080.htm)
- 2015.07 [hexblog] [Hack of the day #0: Somewhat-automating pseudocode HTML generation, with IDAPython.](http://www.hexblog.com/?p=921)
- 2015.06 [msreverseengineering_blog] [Transparent Deobfuscation with IDA Processor Module Extensions](http://www.msreverseengineering.com/blog/2015/6/29/transparent-deobfuscation-with-ida-processor-module-extensions)
- 2015.02 [pediy_new_digest] [[原创]使用IDA PRO+OllyDbg+PEview 追踪windows API 动态链接库函数的调用过程。](https://bbs.pediy.com/thread-197829.htm)
- 2014.12 [hexblog] [Augmenting IDA UI with your own actions.](http://www.hexblog.com/?p=886)
- 2014.10 [vexillium] [SECURE 2014 slide deck and Hex-Rays IDA Pro advisories published](https://j00ru.vexillium.org/2014/10/secure-2014-slide-deck-and-hex-rays-ida-pro-advisories-published/)
- 2014.10 [pediy_new_digest] [[原创]解决IDA的F5(hexray 1.5)不能用于FPU栈用满的情况](https://bbs.pediy.com/thread-193414.htm)
- 2014.08 [3xp10it_archive] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it_archive] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it_archive] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.08 [3xp10it_archive] [ida插件使用备忘录](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/27/ida%E6%8F%92%E4%BB%B6%E4%BD%BF%E7%94%A8%E5%A4%87%E5%BF%98%E5%BD%95/)
- 2014.08 [3xp10it_archive] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.08 [3xp10it_archive] [ida通过usb调试ios下的app](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2017/12/25/ida%E9%80%9A%E8%BF%87usb%E8%B0%83%E8%AF%95ios%E4%B8%8B%E7%9A%84app/)
- 2014.08 [3xp10it_archive] [ida批量下断点追踪函数调用](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/12/21/ida%E6%89%B9%E9%87%8F%E4%B8%8B%E6%96%AD%E7%82%B9%E8%BF%BD%E8%B8%AA%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8/)
- 2014.07 [hexblog] [IDA Dalvik debugger: tips and tricks](http://www.hexblog.com/?p=809)
- 2014.04 [hexblog] [Extending IDAPython in IDA 6.5: Be careful about the GIL](http://www.hexblog.com/?p=788)
- 2014.03 [zdziarski] [The Importance of Forensic Tools Validation](https://www.zdziarski.com/blog/?p=3112)
- 2014.03 [evilsocket] [Programmatically Identifying and Isolating Functions Inside Executables Like IDA Does.](https://www.evilsocket.net/2014/03/11/programmatically-identifying-and-isolating-functions-inside-executables-like-ida-does/)
- 2014.02 [silentsignal_blog] [From Read to Domain Admin – Abusing Symantec Backup Exec with Frida](https://blog.silentsignal.eu/2014/02/27/from-read-to-domain-admin-abusing-symantec-backup-exec-with-frida/)
- 2013.12 [hexblog] [Interacting with IDA through IPC channels](http://www.hexblog.com/?p=773)
- 2013.06 [trustwave_SpiderLabs_Blog] [使用IDA调试Android库](https://www.trustwave.com/Resources/SpiderLabs-Blog/Debugging-Android-Libraries-using-IDA/)
- 2013.05 [v0ids3curity] [Defeating anti-debugging techniques using IDA and x86 emulator plugin](https://www.voidsecurity.in/2013/05/defeating-anti-debugging-techniques.html)
- 2013.05 [hexblog] [Loading your own modules from your IDAPython scripts with idaapi.require()](http://www.hexblog.com/?p=749)
- 2013.04 [hexblog] [Installing PIP packages, and using them from IDA on a 64-bit machine](http://www.hexblog.com/?p=726)
- 2013.03 [pediy_new_digest] [[原创]IDA Demo6.4破解笔记](https://bbs.pediy.com/thread-167109.htm)
- 2012.11 [redplait] [pyside for ida pro 6.3 - part 2](http://redplait.blogspot.com/2012/11/pyside-for-ida-pro-63-part-2.html)
- 2012.10 [redplait] [AVX/XOP instructions processor extender for IDA Pro](http://redplait.blogspot.com/2012/10/avxxop-instructions-processor-extender.html)
- 2012.10 [redplait] [IDA Pro 6.3 SDK is broken ?](http://redplait.blogspot.com/2012/10/ida-pro-63-sdk-is-broken.html)
- 2012.10 [redplait] [pyside for ida pro 6.3](http://redplait.blogspot.com/2012/10/pyside-for-ida-pro-63.html)
- 2012.09 [redplait] [IDA loader of .dcu files from XE3](http://redplait.blogspot.com/2012/09/ida-loader-of-dcu-files-from-xe3.html)
- 2012.08 [tencent_security_blog] [浅谈IDA脚本在漏洞挖掘中的应用](https://security.tencent.com/index.php/blog/msg/4)
- 2012.07 [cr4] [VMware + GDB stub + IDA](http://blog.cr4.sh/2012/07/vmware-gdb-stub-ida.html)
- 2012.06 [pediy_new_digest] [[原创]PRX loader for IDA](https://bbs.pediy.com/thread-152647.htm)
- 2012.06 [pediy_new_digest] [[翻译]API Call Tracing - PEfile, PyDbg and IDAPython](https://bbs.pediy.com/thread-151870.htm)
- 2012.05 [redplait] [dcu files loader for ida pro v2](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro-v2.html)
- 2012.05 [redplait] [dcu files loader for ida pro](http://redplait.blogspot.com/2012/05/dcu-files-loader-for-ida-pro.html)
- 2012.03 [redplait] [updated perl binding for IDA Pro](http://redplait.blogspot.com/2012/03/updated-perl-binding-for-ida-pro.html)
- 2012.03 [pediy_new_digest] [[原创]IDA批量模式](https://bbs.pediy.com/thread-147777.htm)
- 2012.02 [pediy_new_digest] [[原创]IDA Android Remote Debug](https://bbs.pediy.com/thread-146721.htm)
- 2012.01 [pediy_new_digest] [[原创]IDA 6.1 bool 及 默认对齐 sizeof 设置永久修复](https://bbs.pediy.com/thread-145188.htm)
- 2011.12 [redplait] [IDA 5.60 PICode analyzer plugin for win64](http://redplait.blogspot.com/2011/12/ida-560-picode-analyzer-plugin-for.html)
- 2011.10 [reverse_archives] [How to create IDA C/C++ plugins with Xcode](https://reverse.put.as/2011/10/31/how-to-create-ida-cc-plugins-with-xcode/)
- 2011.10 [pediy_new_digest] [[转帖]IDA PRO 6.1 远程调试 Android](https://bbs.pediy.com/thread-141739.htm)
- 2011.09 [pediy_new_digest] [[推荐]IDA sp-analysis failed 不能F5的 解决方案之(一)](https://bbs.pediy.com/thread-140002.htm)
- 2011.08 [pediy_new_digest] [[原创]用IDA Pro + OD 来分析扫雷](https://bbs.pediy.com/thread-138855.htm)
- 2011.08 [pediy_new_digest] [[原创]IDA + GDBServer实现iPhone程序远程调试](https://bbs.pediy.com/thread-138472.htm)
- 2011.08 [redplait] [perl inside IDA Pro](http://redplait.blogspot.com/2011/08/perl-inside-ida-pro.html)
- 2011.07 [redplait] [несколько pdb в ida pro](http://redplait.blogspot.com/2011/07/pdb-ida-pro.html)
- 2011.07 [pediy_new_digest] [[原创]IDA + Debug 插件 实现64Bit Exe脱壳](https://bbs.pediy.com/thread-137416.htm)
- 2011.06 [pediy_new_digest] [[翻译]使用VMWare GDB和IDA调试Windows内核](https://bbs.pediy.com/thread-135229.htm)
- 2011.05 [pediy_new_digest] [[分享]IDA 6.1 版本不能F5的解决办法](https://bbs.pediy.com/thread-134363.htm)
- 2011.05 [pediy_new_digest] [[原创]IDAPython+OdbgScript动态获取程序执行流程](https://bbs.pediy.com/thread-134171.htm)
- 2011.03 [pediy_new_digest] [[原创]Ida Pro Advanced 6.0 中木马分析](https://bbs.pediy.com/thread-131195.htm)
- 2011.03 [pediy_new_digest] [[原创]IDA SDK合并jmp乱序插件代码示例阅读](https://bbs.pediy.com/thread-131016.htm)
- 2011.01 [hexblog] [IDA & Qt: Under the hood](http://www.hexblog.com/?p=250)
- 2010.12 [pediy_new_digest] [[原创]ida 静态分析 破除时间限制](https://bbs.pediy.com/thread-126668.htm)
- 2010.10 [pediy_new_digest] [[下载]IDA pro代码破解揭秘的随书例子下载](https://bbs.pediy.com/thread-123432.htm)
- 2010.10 [hexblog] [Calculating API hashes with IDA Pro](http://www.hexblog.com/?p=193)
- 2010.09 [publicintelligence] [(U//FOUO) FBI Warning: Extremists Likely to Retaliate Against Florida Group’s Planned “International Burn A Koran Day”](https://publicintelligence.net/ufouo-fbi-warning-extremists-likely-to-retaliate-against-florida-group%e2%80%99s-planned-%e2%80%9cinternational-burn-a-koran-day%e2%80%9d/)
- 2010.08 [mattoh] [Exporting IDA function for IDC Script Usage](https://mattoh.wordpress.com/2010/08/06/exporting-ida-function-for-idc-script-usage/)
- 2010.07 [hexblog] [Implementing command completion for IDAPython](http://www.hexblog.com/?p=129)
- 2010.07 [hexblog] [Running scripts from the command line with idascript](http://www.hexblog.com/?p=128)
- 2010.06 [hexblog] [Extending IDC and IDAPython](http://www.hexblog.com/?p=126)
- 2010.04 [hexblog] [Kernel debugging with IDA Pro / Windbg plugin and VirtualKd](http://www.hexblog.com/?p=123)
- 2010.03 [hexblog] [Using custom viewers from IDAPython](http://www.hexblog.com/?p=119)
- 2010.01 [hexblog] [Debugging ARM code snippets in IDA Pro 5.6 using QEMU emulator](http://www.hexblog.com/?p=111)
- 2009.12 [pediy_new_digest] [[原创]Symbian_Remote_Debugger_With_IDA](https://bbs.pediy.com/thread-103934.htm)
- 2009.10 [pediy_new_digest] [[原创]IDA学习笔记](https://bbs.pediy.com/thread-99560.htm)
- 2009.09 [hexblog] [Develop your master boot record and debug it with IDA Pro and the Bochs debugger plugin](http://www.hexblog.com/?p=103)
- 2009.02 [hexblog] [Advanced Windows Kernel Debugging with VMWare and IDA’s GDB debugger](http://www.hexblog.com/?p=94)
- 2008.10 [evilcodecave] [IDA Pro Enhances Hostile Code Analysis Support](https://evilcodecave.wordpress.com/2008/10/04/ida-pro-enhances-hostile-code-analysis-support/)
- 2008.09 [pediy_new_digest] [[原创]ShellCode Locator for IDA 5.2](https://bbs.pediy.com/thread-72947.htm)
- 2008.08 [evilcodecave] [IDA Debugger Malformed SEH Causes Crash](https://evilcodecave.wordpress.com/2008/08/31/ida-debugger-malformed-seh-causes-crash/)
- 2008.04 [pediy_new_digest] [[原创]idb_2_pat for ida pro V5.2](https://bbs.pediy.com/thread-62825.htm)
- 2007.08 [pediy_new_digest] [[原创]基于 ida 的反汇编转换 Obj 的可行性 笔记(1)](https://bbs.pediy.com/thread-49910.htm)
- 2007.04 [pediy_new_digest] [[翻译]Pinczakko的AwardBIOS逆向工程指导](https://bbs.pediy.com/thread-42166.htm)
- 2007.02 [pediy_new_digest] [IDA Plugin 编写基础](https://bbs.pediy.com/thread-38900.htm)
- 2006.09 [pediy_new_digest] [[翻译]Using IDA Pro's Debugger](https://bbs.pediy.com/thread-31667.htm)
- 2006.09 [pediy_new_digest] [[翻译]Customizing IDA Pro](https://bbs.pediy.com/thread-31658.htm)
- 2006.08 [msreverseengineering_blog] [Defeating HyperUnpackMe2 with an IDA Processor Module](http://www.msreverseengineering.com/blog/2014/8/5/defeating-hyperunpackme2-with-an-ida-processor-module)
- 2004.11 [pediy_new_digest] [又说 IDA 边界修改插件](https://bbs.pediy.com/thread-7150.htm)


***


## <a id="a4bd25d3dc2f0be840e39674be67d66b"></a>Tips&&Tricks


- 2019.07 [hexacorn] [Batch decompilation with IDA / Hex-Rays Decompiler](http://www.hexacorn.com/blog/2019/07/04/batch-decompilation-with-ida-hex-rays-decompiler/)
- 2019.06 [openanalysis] [Disable ASLR for Easier Malware Debugging With x64dbg and IDA Pro](https://oalabs.openanalysis.net/2019/06/12/disable-aslr-for-easier-malware-debugging/)
- 2019.06 [youtube_OALabs] [Disable ASLR For Easier Malware Debugging With x64dbg and IDA Pro](https://www.youtube.com/watch?v=DGX7oZvdmT0)
- 2019.06 [openanalysis] [Reverse Engineering C++ Malware With IDA Pro: Classes, Constructors, and Structs](https://oalabs.openanalysis.net/2019/06/03/reverse-engineering-c-with-ida-pro-classes-constructors-and-structs/)
- 2019.06 [youtube_OALabs] [Reverse Engineering C++ Malware With IDA Pro](https://www.youtube.com/watch?v=o-FFGIloxvE)
- 2019.03 [aliyun_xz] [IDA Pro7.0使用技巧总结](https://xz.aliyun.com/t/4205)
- 2018.06 [checkpoint_research] [Scriptable Remote Debugging with Windbg and IDA Pro](https://research.checkpoint.com/scriptable-remote-debugging-windbg-ida-pro/)
- 2015.07 [djmanilaice] [在PyCharm中编写IDAPython脚本时自动提示](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [使用IDA自动打开当前目录下的DLL和EXE](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


***


## <a id="0b3e1936ad7c4ccc10642e994c653159"></a>恶意代码分析


- 2019.04 [360_anquanke_learning] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [使用IDAPython分析Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
- 2019.01 [youtube_OALabs] [Lazy String Decryption Tips With IDA PRO and Shade Ransomware Unpacked!](https://www.youtube.com/watch?v=RfnuMhosxuQ)
- 2018.09 [4hou] [Hidden Bee恶意软件家族的定制IDA装载模块开发](http://www.4hou.com/technology/13438.html)
- 2018.09 [4hou] [用IDAPython解密Gootkit中的字符串](http://www.4hou.com/technology/13209.html)
- 2018.05 [youtube_OALabs] [Unpacking Gootkit Part 2 - Debugging Anti-Analysis Tricks With IDA Pro and x64dbg](https://www.youtube.com/watch?v=QgUlPvEE4aw)
- 2018.04 [youtube_OALabs] [Unpacking VB6 Packers With IDA Pro and API Hooks (Re-Upload)](https://www.youtube.com/watch?v=ylWInOcQy2s)
- 2018.03 [youtube_OALabs] [Unpacking Gootkit Malware With IDA Pro and X64dbg - Subscriber Request](https://www.youtube.com/watch?v=242Tn0IL2jE)
- 2018.01 [youtube_OALabs] [Unpacking Pykspa Malware With Python and IDA Pro - Subscriber Request Part 1](https://www.youtube.com/watch?v=HfSQlC76_s4)
- 2017.11 [youtube_OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 2)](https://www.youtube.com/watch?v=kdNQhfgoQoU)
- 2017.11 [youtube_OALabs] [Unpacking Process Injection Malware With IDA PRO (Part 1)](https://www.youtube.com/watch?v=ScBB-Hi7NxQ)
- 2017.06 [hackers_arise] [Reverse Engineering Malware, Part 3:  IDA Pro Introduction](https://www.hackers-arise.com/single-post/2017/06/22/Reverse-Engineering-Malware-Part-3-IDA-Pro-Introduction)
- 2017.05 [4hou] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](http://www.4hou.com/technology/4832.html)
- 2017.05 [3gstudent] [逆向分析——使用IDA动态调试WanaCrypt0r中的tasksche.exe](https://3gstudent.github.io/3gstudent.github.io/%E9%80%86%E5%90%91%E5%88%86%E6%9E%90-%E4%BD%BF%E7%94%A8IDA%E5%8A%A8%E6%80%81%E8%B0%83%E8%AF%95WanaCrypt0r%E4%B8%AD%E7%9A%84tasksche.exe/)
- 2012.06 [trustwave_SpiderLabs_Blog] [使用IDAPython对Flame的字符串进行反混淆](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


***


## <a id="04cba8dbb72e95d9c721fe16a3b48783"></a>系列文章-Labeless插件介绍


- 2018.10 [checkpoint] [Labeless Part 6: How to Resolve Obfuscated API Calls in the Ngioweb Proxy Malware - Check Point Research](https://research.checkpoint.com/labeless-part-6-how-to-resolve-obfuscated-api-calls-in-the-ngioweb-proxy-malware/)
- 2018.10 [checkpoint] [Labeless Part 5: How to Decrypt Strings in Boleto Banking Malware Without Reconstructing Decryption Algorithm. - Check Point Research](https://research.checkpoint.com/labeless-part-5-how-to-decrypt-strings-in-boleto-banking-malware-without-reconstructing-decryption-algorithm/)
- 2018.10 [checkpoint] [Labeless Part 4: Scripting - Check Point Research](https://research.checkpoint.com/labeless-part-4-scripting/)
- 2018.08 [checkpoint] [Labeless Part 3: How to Dump and Auto-Resolve WinAPI Calls in LockPos Point-of-Sale Malware - Check Point Research](https://research.checkpoint.com/19558-2/)
- 2018.08 [checkpoint] [Labeless Part 2: Installation - Check Point Research](https://research.checkpoint.com/installing-labeless/)
- 2018.08 [checkpoint] [Labeless Part 1: An Introduction - Check Point Research](https://research.checkpoint.com/labeless-an-introduction/)


***


## <a id="1a2e56040cfc42c11c5b4fa86978cc19"></a>系列文章-使用IDA从零开始学逆向


- 2019.11 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P25)](https://medium.com/p/304110bdf635)
- 2019.10 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P24)](https://medium.com/p/66451e50163e)
- 2019.10 [tradahacking] [REVERSING WITH IDA FROM SCRATCH (P23)](https://medium.com/p/a03897f960be)
- 2019.09 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P21)](https://medium.com/p/17ce2ee804af)
- 2019.08 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P20)](https://medium.com/p/adc2bad58cc3)
- 2019.08 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P19)](https://medium.com/p/b8a5ccc0efbc)
- 2019.07 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P18)](https://medium.com/p/b9b5987eea22)
- 2019.07 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P17)](https://medium.com/p/13aae3c33824)
- 2019.06 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P16)](https://medium.com/p/66c697636724)
- 2019.06 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P15)](https://medium.com/p/9bb2bbdf6fbc)
- 2019.05 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P14)](https://medium.com/p/fd20c144c844)
- 2019.05 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P13)](https://medium.com/p/adc88403c295)
- 2019.04 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P12)](https://medium.com/p/6b19df3db60e)
- 2019.04 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P11)](https://medium.com/p/34e6214132d6)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P10)](https://medium.com/p/f054072cc4cd)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P9)](https://medium.com/p/3ead456499d2)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P8)](https://medium.com/p/c627c70b5efd)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P7)](https://medium.com/p/986cb6c09405)
- 2019.03 [tradahacking] [REVERSING WITH IDA FROM SCRATCH (P6)](https://medium.com/p/ec232b87a091)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P5)](https://medium.com/p/f153835b4ffc)
- 2019.03 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P4)](https://medium.com/p/3a7e726e197b)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P3)](https://medium.com/p/181f78a4fac7)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P2)](https://medium.com/p/971d62a4c94a)
- 2019.02 [kienbigmummy] [REVERSING WITH IDA FROM SCRATCH (P1)](https://medium.com/p/a0360893d2d5)


***


## <a id="e838a1ecdcf3d068547dd0d7b5c446c6"></a>系列文章-IDAPython-让你的生活更美好


### <a id="7163f7c92c9443e17f3f76cc16c2d796"></a>原文


- 2016.06 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part6](https://unit42.paloaltonetworks.com/unit42-using-idapython-to-make-your-life-easier-part-6/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part5](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-5/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part4](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-4/)
- 2016.01 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part3](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-3/)
- 2015.12 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part2](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-2/)
- 2015.12 [paloaltonetworks] [ Using IDAPython to Make Your Life Easier, Part1](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/)


### <a id="fc62c644a450f3e977af313edd5ab124"></a>译文


- 2016.01 [freebuf] [IDAPython：让你的生活更美好（五）](http://www.freebuf.com/articles/system/93440.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（四）](http://www.freebuf.com/articles/system/92505.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（三）](http://www.freebuf.com/articles/system/92488.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（二）](http://www.freebuf.com/sectool/92168.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（一）](http://www.freebuf.com/sectool/92107.html)




***


## <a id="8433dd5df40aaf302b179b1fda1d2863"></a>系列文章-使用IDA逆向C代码


- 2019.01 [ly0n] [Reversing C code with IDA part V](https://paumunoz.tech/2019/01/12/reversing-c-code-with-ida-part-v/)
- 2019.01 [ly0n] [Reversing C code with IDA part IV](https://paumunoz.tech/2019/01/07/reversing-c-code-with-ida-part-iv/)
- 2019.01 [ly0n] [Reversing C code with IDA part III](https://paumunoz.tech/2019/01/02/reversing-c-code-with-ida-part-iii/)
- 2018.12 [ly0n] [Reversing C code with IDA part II](https://paumunoz.tech/2018/12/31/reversing-c-code-with-ida-part-ii/)
- 2018.01 [ly0n] [Reversing C code with IDA part I](https://paumunoz.tech/2018/01/11/reversing-c-code-with-ida-part-i/)


***


## <a id="3d3bc775abd7f254ff9ff90d669017c9"></a>工具&&插件&&脚本介绍


- 2019.10 [vmray_blog] [VMRay IDA Plugin v1.1: Streamlining Deep-Dive Malware Analysis](https://www.vmray.com/cyber-security-blog/vmray-ida-plugin-v1-1-streamlining-deep-dive-malware-analysis/)
- 2019.10 [talosintelligence_blog] [New IDA Pro plugin provides TileGX support](https://blog.talosintelligence.com/2019/10/new-ida-pro-plugin-provides-tilegx.html)
- 2019.09 [talosintelligence_blog] [GhIDA: Ghidra decompiler for IDA Pro](https://blog.talosintelligence.com/2019/09/ghida.html)
- 2019.04 [_0xeb] [climacros – IDA productivity tool](http://0xeb.net/2019/04/climacros-ida-productivity-tool/)
- 2019.04 [_0xeb] [QScripts – IDA Scripting productivity tool](http://0xeb.net/2019/04/ida-qscripts/)
- 2019.03 [_0xeb] [Daenerys: IDA Pro and Ghidra interoperability framework](http://0xeb.net/2019/03/daenerys-ida-pro-and-ghidra-interoperability-framework/)
- 2019.02 [kitploit_home] [HexRaysCodeXplorer - Hex-Rays Decompiler Plugin For Better Code Navigation](https://www.kitploit.com/2019/02/hexrayscodexplorer-hex-rays-decompiler.html)
- 2019.02 [kitploit_home] [Ponce - IDA Plugin For Symbolic Execution Just One-Click Away!](https://www.kitploit.com/2019/02/ponce-ida-plugin-for-symbolic-execution.html)
- 2019.01 [talosintelligence_blog] [Dynamic Data Resolver (DDR) - IDA Plugin](https://blog.talosintelligence.com/2019/01/ddr.html)
- 2018.12 [securityonline] [HexRaysCodeXplorer: Hex-Rays Decompiler plugin for better code navigation](https://securityonline.info/codexplorer/)
- 2018.11 [4hou] [FLARE脚本系列：使用idawasm IDA Pro插件逆向WebAssembly（Wasm）模块](http://www.4hou.com/reverse/13935.html)
- 2018.10 [aliyun_xz] [用idawasm IDA Pro逆向WebAssembly模块](https://xz.aliyun.com/t/2854)
- 2018.10 [fireeye_threat_research] [FLARE Script Series: Reverse Engineering WebAssembly Modules Using the
idawasm IDA Pro Plugin](https://www.fireeye.com/blog/threat-research/2018/10/reverse-engineering-webassembly-modules-using-the-idawasm-ida-pro-plugin.html)
- 2018.10 [vmray_blog] [Introducing the IDA Plugin for VMRay Analyzer](https://www.vmray.com/cyber-security-blog/ida-plugin-vmray-analyzer/)
- 2018.09 [ptsecurity_blog] [How we developed the NIOS II processor module for IDA Pro](http://blog.ptsecurity.com/2018/09/how-we-developed-nios-ii-processor.html)
- 2018.09 [talosintelligence_blog] [IDA-minsc Wins Second Place in Hex-Rays Plugins Contest](https://blog.talosintelligence.com/2018/09/ida-minsc.html)
- 2018.09 [msreverseengineering_blog] [Weekend Project: A Custom IDA Loader Module for the Hidden Bee Malware Family](http://www.msreverseengineering.com/blog/2018/9/2/weekend-project-a-custom-ida-loader-module-for-the-hidden-bee-malware-family)
- 2018.08 [360_anquanke_learning] [Lua程序逆向之为Luac编写IDA Pro处理器模块](https://www.anquanke.com/post/id/153699/)
- 2018.06 [dougallj] [编写IDA反编译插件之: 处理VMX指令](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
- 2018.05 [freebuf] [HeapViewer：一款专注于漏洞利用开发的IDA Pro插件](http://www.freebuf.com/sectool/171632.html)
- 2018.03 [pediy_new_digest] [[翻译]使用 IDAPython 写一个简单的x86模拟器](https://bbs.pediy.com/thread-225091.htm)
- 2018.03 [_0xeb] [Using Z3 with IDA to simplify arithmetic operations in functions](http://0xeb.net/2018/03/using-z3-with-ida-to-simplify-arithmetic-operations-in-functions/)
- 2018.02 [securityonline] [IDAPython Embedded Toolkit: IDAPython scripts for automating analysis of firmware of embedded devices](https://securityonline.info/idapython-embedded-toolkit-idapython-scripts-for-automating-analysis-of-firmware-of-embedded-devices/)
- 2018.02 [_0xeb] [Writing a simple x86 emulator with IDAPython](http://0xeb.net/2018/02/writing-a-simple-x86-emulator-with-idapython/)
- 2018.01 [fireeye_threat_research] [FLARE IDA Pro Script Series: Simplifying Graphs in IDA](https://www.fireeye.com/blog/threat-research/2018/01/simplifying-graphs-in-ida.html)
- 2017.12 [ret2] [What's New in Lighthouse v0.7](http://blog.ret2.io/2017/12/07/lighthouse-v0.7/)
- 2017.12 [youtube_OALabs] [Using Yara Rules With IDA Pro - New Tool!](https://www.youtube.com/watch?v=zAKi9KWYyfM)
- 2017.11 [youtube_hasherezade] [IFL - Interactive Functions List - a plugin for IDA Pro](https://www.youtube.com/watch?v=L6sROW_MivE)
- 2017.11 [securityonline] [IDA EA: A set of exploitation/reversing aids for IDA](https://securityonline.info/ida-ea-exploitation-reversing-ida/)
- 2017.06 [reverse_archives] [EFISwissKnife 介绍](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
- 2017.04 [redplait] [etwex - ida plugin for Etw traces IIDs searching](http://redplait.blogspot.com/2017/04/etwex-ida-plugin-for-etw-traces-iids.html)
- 2017.04 [360_anquanke_learning] [IDAPython：一个可以解放双手的 IDA 插件](https://www.anquanke.com/post/id/85890/)
- 2017.03 [duksctf] [Make IDA Pro Great Again](http://duksctf.github.io/2017/03/15/Make-IDA-Pro-Great-Again.html)
- 2017.03 [redplait] [ida plugin for RFG fixups processing](http://redplait.blogspot.com/2017/03/ida-plugin-for-rfg-fixups-processing.html)
- 2017.02 [argus_sec] [Collaborative Reverse Engineering with PSIDA - Argus Cyber Security](https://argus-sec.com/collaborative-reverse-engineering-psida/)
- 2016.01 [eugenekolo] [A walk through the binary with IDA](https://eugenekolo.com/blog/a-walk-through-the-binary-with-ida/)
- 2015.12 [360_anquanke_learning] [适用于IDA Pro的CGEN框架](https://www.anquanke.com/post/id/83210/)
- 2015.12 [freebuf] [FLARE IDA Pro的脚本系列：自动化提取函数参数](http://www.freebuf.com/sectool/89273.html)
- 2015.04 [nul] [VMProtect + IDA Pro　做一回强悍的加密](http://www.nul.pw/2015/04/29/86.html)
- 2015.03 [joxeankoret] [Diaphora, a program diffing plugin for IDA Pro](http://joxeankoret.com/blog/2015/03/13/diaphora-a-program-diffing-plugin-for-ida-pro/)
- 2014.10 [devttys0] [A Code Signature Plugin for IDA](http://www.devttys0.com/2014/10/a-code-signature-plugin-for-ida/)
- 2014.09 [freebuf] [火眼（FireEye）实验室FLARE IDA Pro脚本系列：MSDN注释插件](http://www.freebuf.com/sectool/43334.html)
- 2014.08 [3xp10it_archive] [ida插件mynav](http://3xp10it.cc/%E4%BA%8C%E8%BF%9B%E5%88%B6/2018/01/22/ida%E6%8F%92%E4%BB%B6mynav/)
- 2014.05 [oct0xor] [Deci3dbg - Ida Pro Debugger Module for Playstation 3](http://oct0xor.github.io/2014/05/30/deci3dbg/)
- 2013.11 [quarkslab_blog] [IDA processor module](https://blog.quarkslab.com/ida-processor-module.html)
- 2013.06 [redplait] [IDA loader of .dcu files from XE4](http://redplait.blogspot.com/2013/06/ida-loader-of-dcu-files-from-xe4.html)
- 2012.07 [reverse_archives] [ExtractMachO: an IDA plugin to extract Mach-O binaries from disassembly](https://reverse.put.as/2012/07/30/extractmacho-an-ida-plugin-to-extract-mach-o-binaries-from-disassembly/)
- 2011.11 [reverse_archives] [Display Mach-O headers plugin for IDA](https://reverse.put.as/2011/11/03/display-mach-o-headers-plugin-for-ida/)
- 2011.04 [hexblog] [VirusTotal plugin for IDA Pro](http://www.hexblog.com/?p=324)
- 2010.05 [joxeankoret] [MyNav, a python plugin for IDA Pro](http://joxeankoret.com/blog/2010/05/02/mynav-a-python-plugin-for-ida-pro/)


***


## <a id="ea11818602eb33e8b165eb18d3710965"></a>翻译-TheIDAProBook


- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy_new_digest] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


***


## <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>翻译-ReverseEngineeringCodeWithIDAPro


- 2009.01 [pediy_new_digest] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy_new_digest] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


***


## <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>逆向实战


- 2019.06 [devco] [破密行動: 以不尋常的角度破解 IDA Pro 偽隨機數](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way/)
- 2019.04 [venus_seebug] [使用 IDA Pro 的 REobjc 模块逆向 Objective-C 二进制文件](https://paper.seebug.org/887/)
- 2018.11 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting - Part 2](http://www.somersetrecon.com/blog/2018/8/2/idapython-part-2)
- 2018.07 [360_anquanke_learning] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [如何使用IDAPython挖掘漏洞](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)
- 2018.03 [duo_blog_duo_labs] [Reversing Objective-C Binaries With the REobjc Module for IDA Pro](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
- 2006.05 [pediy_new_digest] [Themida v1008 驱动程序分析,去除花指令的 IDA 文件](https://bbs.pediy.com/thread-25836.htm)


# 贡献
内容为系统自动导出, 有任何问题请提issue