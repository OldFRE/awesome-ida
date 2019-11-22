# ida


IDA Resource Collection. 450+ open source tools, ~300 blog posts.


# 说明
[中文版本](https://github.com/xrkk/awesome-ida/blob/master/Readme.md)


# Directory
- [Tools](#f11ab1ff46aa300cc3e86528b8a98ad7)
    - [RecentAdd](#c39dbae63d6a3302c4df8073b4d1cdc8)
    - [(93) NoCategory](#c39a6d8598dde6abfeef43faf931beb5)
    - [Structure&&Class](#fb4f0c061a72fc38656691746e7c45ce)
        - [(6) NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb)
        - [(8) C++Class&&VirtualTable](#4900b1626f10791748b20630af6d6123)
    - [(3) Collection](#a7dac37cd93b8bb42c7d6aedccb751b3)
    - [(9) Skin&&Theme](#fabf03b862a776bbd8bcc4574943a65a)
    - [(4) Firmware&&EmbedDevice](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e)
    - [Signature(FLIRT...)&&Diff&&Match](#02088f4884be6c9effb0f1e9a3795e58)
        - [(17) NoCategory](#cf04b98ea9da0056c055e2050da980c1)
        - [FLIRT](#19360afa4287236abe47166154bc1ece)
            - [(3) FLIRTSignatureCollection](#1c9d8dfef3c651480661f98418c49197)
            - [(2) FLIRTSignatureGenerate](#a9a63d23d32c6c789ca4d2e146c9b6d0)
        - [(11) Diff&&Match](#161e5a3437461dc8959cc923e6a18ef7)
        - [(7) Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a)
    - [(6) IDB](#5e91b280aab7f242cbc37d64ddbff82f)
    - [(5) CollaborativeRE](#206ca17fc949b8e0ae62731d9bb244cb)
    - [(9) SyncWithDebugger](#f7d311685152ac005cfce5753c006e4b)
    - [ImportExport&&SyncWithOtherTools](#6fb7e41786c49cc3811305c520dfe9a1)
        - [(13) NoCategory](#8ad723b704b044e664970b11ce103c09)
        - [(5) Ghidra](#c7066b0c388cd447e980bf0eb38f39ab)
        - [(3) BinNavi](#11139e7d6db4c1cef22718868f29fe12)
        - [(3) BinaryNinja](#d1ff64bee76f6749aef6100d72bfbe3a)
        - [(2) Radare2](#21ed198ae5a974877d7a635a4b039ae3)
        - [(3) Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd)
        - [(2) IntelPin](#dd0332da5a1482df414658250e6357f8)
    - [SpecificTarget](#004c199e1dbf71769fbafcd8e58d1ead)
        - [(24) NoCategory](#5578c56ca09a5804433524047840980e)
        - [(2) GoLang](#1b17ac638aaa09852966306760fda46b)
        - [(4) WindowsDriver](#4c158ccc5aee04383755851844fdd137)
        - [(4) PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5)
        - [(32) Loader&Processor](#cb59d84840e41330a7b5e275c0b81725)
        - [(4) PDB](#f5e51763bb09d8fd47ee575a98bedca1)
        - [(2) Flash&&SWF](#7d0681efba2cf3adaba2780330cd923a)
        - [(4) MalwareFamily](#841d605300beba45c3be131988514a03)
        - [(1) CTF](#ad44205b2d943cfa2fa805b2643f4595)
    - [IDAPython](#ad68872e14f70db53e8d9519213ec039)
        - [(8) NoCategory](#2299bc16945c25652e5ad4d48eae8eca)
        - [(1) cheatsheets](#c42137cf98d6042372b1fd43c3635135)
    - [(6) InstructRef&&Doc](#846eebe73bef533041d74fc711cafb43)
    - [ScriptWritting](#c08ebe5b7eec9fc96f8eff36d1d5cc7d)
        - [(9) NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2)
        - [(3) Qt](#1a56a5b726aaa55ec5b7a5087d6c8968)
        - [(3) Console&&GUI](#1721c09501e4defed9eaa78b8d708361)
        - [(2) Template](#227fbff77e3a13569ef7b007344d5d2e)
        - [(2) OtherLang](#8b19bb8cf9a5bc9e6ab045f3b4fabf6a)
    - [(16) Ancient](#dc35a2b02780cdaa8effcae2b6ce623e)
    - [Debug&&DynamicData](#e3e7030efc3b4de3b5b8750b7d93e6dd)
        - [(10) NoCategory](#2944dda5289f494e5e636089db0d6a6a)
        - [(10) DBIData](#0fbd352f703b507853c610a664f024d1)
        - [(4) DebuggerData](#b31acf6c84a9506066d497af4e702bf5)
    - [(13) Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9)
    - [(7) DeObfuscate](#7199e8787c0de5b428f50263f965fda7)
    - [Nav&&QuickAccess&&Graph&&Image](#fcf75a0881617d1f684bc8b359c684d7)
        - [(15) NoCategory](#c5b120e1779b928d860ad64ff8d23264)
        - [(9) GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f)
        - [(3) Graph](#3b1dba00630ce81cba525eea8fcdae08)
        - [(3) Search](#8f9468e9ab26128567f4be87ead108d7)
    - [(7) Android](#66052f824f5054aa0f70785a2389a478)
    - [Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O](#2adc0044b2703fb010b3bf73b1f1ea4a)
        - [(5) NoCategory](#8530752bacfb388f3726555dc121cb1a)
        - [(3) kernelCache](#82d0fa2d6934ce29794a651513934384)
        - [(3) Mach-O](#d249a8d09a3f25d75bb7ba8b32bd9ec5)
        - [(2) Swift](#1c698e298f6112a86c12881fbd8173c7)
    - [(9) ELF](#e5e403123c70ddae7bd904d3a3005dbb)
    - [(5) Microcode](#7a2977533ccdac70ee6e58a7853b756b)
    - [(6) Emulator](#b38dab81610be087bd5bc7785269b8cc)
    - [(4) PartOfOtherTool](#83de90385d03ac8ef27360bfcdc1ab48)
    - [Vul](#1ded622dca60b67288a591351de16f8b)
        - [(7) NoCategory](#385d6777d0747e79cccab0a19fa90e7e)
        - [(2) ROP](#cf2efa7e3edb24975b92d2e26ca825d2)
    - [(7) Patch](#7d557bc3d677d206ef6c5a35ca8b3a14)
    - [(3) Other](#7dfd8abad50c14cd6bdc8d8b79b6f595)
    - [Function](#90bf5d31a3897400ac07e15545d4be02)
        - [(4) NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae)
        - [(6) Rename&&Prefix&&Tag](#73813456eeb8212fd45e0ea347bec349)
        - [(5) Nav&&Search](#e4616c414c24b58626f834e1be079ebc)
        - [(2) demangle](#cadae88b91a57345d266c68383eb05c5)
    - [(3) TaintAnalysis&&SymbolicExecution](#34ac84853604a7741c61670f2a075d20)
    - [(8) string](#9dcc6c7dd980bec1f92d0cc9a2209a24)
    - [(3) encrypt&&decrypt](#06d2caabef97cf663bd29af2b1fe270c)
- [Video&&Post](#18c6a45392d6b383ea24b363d2f3e76b)
    - [(146) NoCategory](#4187e477ebc45d1721f045da62dbf4e8)
    - [(9) Tips&&Tricks](#a4bd25d3dc2f0be840e39674be67d66b)
    - [(15) Malware](#0b3e1936ad7c4ccc10642e994c653159)
    - [(6) Series-LabelessIntroduction](#04cba8dbb72e95d9c721fe16a3b48783)
    - [(24) Series-ReversingWithIDAFromScrach](#1a2e56040cfc42c11c5b4fa86978cc19)
    - [Series-UsingIDAPythonToMakeYourLifeEasier](#e838a1ecdcf3d068547dd0d7b5c446c6)
        - [(6) Original](#7163f7c92c9443e17f3f76cc16c2d796)
        - [(5) ZH](#fc62c644a450f3e977af313edd5ab124)
    - [(5) Series-ReversingCCodeWithIDA](#8433dd5df40aaf302b179b1fda1d2863)
    - [(50) Tool&&Plugin&&Script](#3d3bc775abd7f254ff9ff90d669017c9)
    - [(5) Translate-TheIDAProBook](#ea11818602eb33e8b165eb18d3710965)
    - [(2) Translate-ReverseEngineeringCodeWithIDAPro](#ec5f7b9ed06500c537aa25851a3f2d3a)
    - [(7) REPractice](#d8e48eb05d72db3ac1e050d8ebc546e1)
- [TODO](#35f8efcff18d0449029e9d3157ac0899)


# <a id="f11ab1ff46aa300cc3e86528b8a98ad7"></a>Tools


- Mainly from Github


***


## <a id="c39dbae63d6a3302c4df8073b4d1cdc8"></a>RecentAdd




***


## <a id="c39a6d8598dde6abfeef43faf931beb5"></a>NoCategory


- [**1037**Star][2m] [Py] [fireeye/flare-ida](https://github.com/fireeye/flare-ida) IDA Pro utilities from FLARE team
    - [StackStrings](https://github.com/fireeye/flare-ida/blob/master/plugins/stackstrings_plugin.py) 自动恢复手动构造的字符串
    - [Struct Typer](https://github.com/fireeye/flare-ida/blob/master/plugins/struct_typer_plugin.py) 
    - [ApplyCalleeType](https://github.com/fireeye/flare-ida/blob/master/python/flare/apply_callee_type.py) This plugin allows you to specify or choose a function type for indirect calls as described here: [Flare-Ida-Pro-Script](https://www.fireeye.com/blog/threat-research/2015/04/flare_ida_pro_script.html)
    - [argtracker](https://github.com/fireeye/flare-ida/blob/master/python/flare/argtracker.py) 识别函数使用的静态参数
    - [idb2pat](https://github.com/fireeye/flare-ida/blob/master/python/flare/idb2pat.py) FLIRT签名生成
    - [objc2_analyzer](https://github.com/fireeye/flare-ida/blob/master/python/flare/objc2_analyzer.py) 在目标Mach-O可执行文件的与Objective-C运行时相关的部分中定义的选择器引用及其实现之间创建交叉引用
    - [MSDN Annotations](https://github.com/fireeye/flare-ida/tree/master/python/flare/IDB_MSDN_Annotator) 从XML文件中提取MSDN信息，添加到IDB数据库中
    - [ironstrings](https://github.com/fireeye/flare-ida/tree/master/python/flare/ironstrings) 使用代码模拟执行（flare-emu）, 恢复构造的字符串
    - [Shellcode Hashes](https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes) 生成Hash数据库
- [**732**Star][6m] [Py] [devttys0/ida](https://github.com/devttys0/ida) None
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
- [**308**Star][30d] [C] [ohjeongwook/darungrim](https://github.com/ohjeongwook/darungrim) A patch analysis tool
    - [IDA插件](https://github.com/ohjeongwook/darungrim/tree/master/Src/IDAPlugin) 
    - [DGEngine](https://github.com/ohjeongwook/darungrim/tree/master/Src/DGEngine) 
- [**295**Star][1y] [C++] [nevermoe/unity_metadata_loader](https://github.com/nevermoe/unity_metadata_loader) None
- [**272**Star][3m] [Py] [jpcertcc/aa-tools](https://github.com/jpcertcc/aa-tools) Artifact analysis tools by JPCERT/CC Analysis Center
    - [apt17scan.py](https://github.com/jpcertcc/aa-tools/blob/master/apt17scan.py) Volatility插件, 检测APT17相关的恶意代码并提取配置
    - [emdivi_postdata_decoder](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_postdata_decoder.py) 解码Emdivi post的数据
    - [emdivi_string_decryptor](https://github.com/jpcertcc/aa-tools/blob/master/emdivi_string_decryptor.py) IDAPython脚本, 解密Emdivi内的字符串
- [**114**Star][1y] [Py] [vallejocc/reverse-engineering-arsenal](https://github.com/vallejocc/Reverse-Engineering-Arsenal) Useful Scripts for helping in reverse engeenering
    - [WinDbg](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/WinDbg) Windbg脚本收集
    - [IDA-set_symbols_for_addresses](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/set_symbols_for_addresses.py) 遍历所有区段查找与指定的（地址，符号）匹配的DWORD地址，并将对应地址的值命名
    - [IDA-stack_strings_deobfuscator_1](https://github.com/vallejocc/Reverse-Engineering-Arsenal/blob/master/IDA/stack_strings_deobfuscator_1.py) 反混淆栈字符串
- [**80**Star][3m] [Py] [takahiroharuyama/ida_haru](https://github.com/takahiroharuyama/ida_haru) scripts for IDA Pro
    - [bindiff](https://github.com/takahiroharuyama/ida_haru/blob/master/bindiff/README.org) 使用BinDiff对多个二进制文件进行对比，可多达100个
    - [eset_crackme](https://github.com/takahiroharuyama/ida_haru/blob/master/eset_crackme/README.org) ESET CrackMe driver VM loader/processor
    - [fn_fuzzy](https://github.com/takahiroharuyama/ida_haru/blob/master/fn_fuzzy/README.org) 快速二进制文件对比
    - [stackstring_static](https://github.com/takahiroharuyama/ida_haru/blob/master/stackstring_static/README.org) 静态恢复栈上的字符串
- [**73**Star][9m] [Py] [secrary/ida-scripts](https://github.com/secrary/ida-scripts) IDAPro scripts/plugins
    - [dumpDyn](https://github.com/secrary/ida-scripts/blob/master/dumpDyn/README.md) 保存动态分配并执行的代码的相关信息：注释、名称、断点、函数等，之后此代码在不同基址执行时使保存内容依然可用
    - [idenLib](https://github.com/secrary/ida-scripts/blob/master/idenLib/README.md) 库函数识别
    - [IOCTL_decode](https://github.com/secrary/ida-scripts/blob/master/IOCTL_decode.py) Windows驱动的IO控制码
    - [XORCheck](https://github.com/secrary/ida-scripts/blob/master/XORCheck.py) 
- [**60**Star][2y] [Py] [tmr232/idabuddy](https://github.com/tmr232/idabuddy) A Reverse-Engineer's best friend.
- [**59**Star][2y] [C++] [alexhude/loadprocconfig](https://github.com/alexhude/loadprocconfig) IDA plugin to load processor configuration files.
- [**57**Star][1m] [Py] [williballenthin/idawilli](https://github.com/williballenthin/idawilli) IDA Pro resources, scripts, and configurations
    - [hint_calls](https://github.com/williballenthin/idawilli/blob/master/plugins/hint_calls/readme.md) 以Hint的形式战士函数引用的call和字符串
    - [dynamic_hints](https://github.com/williballenthin/idawilli/blob/master/plugins/dynamic_hints/readme.md) 演示如何为动态数据提供自定义hint的示例插件
    - [add_segment](https://github.com/williballenthin/idawilli/tree/master/scripts/add_segment) 将已存在文件的内容添加为新的segment
    - [color](https://github.com/williballenthin/idawilli/tree/master/scripts/color) 对指令进行着色
    - [find_ptrs](https://github.com/williballenthin/idawilli/tree/master/scripts/find_ptrs) 扫描.text区段查找可能为指针的值,并进行标记
    - [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn) 创建yara规则，匹配当前函数的basic block
- [**54**Star][1y] [Py] [zardus/idalink](https://github.com/zardus/idalink) Some glue facilitating remote use of IDA (the Interactive DisAssembler) Python API.
- [**52**Star][3y] [C++] [sektioneins/wwcd](https://github.com/sektioneins/wwcd) What Would Capstone Decode - IDA plugin that implements a Capstone powered IDA view
- [**51**Star][2y] [Py] [cseagle/ida_clemency](https://github.com/cseagle/ida_clemency) IDA cLEMENCy Tools
- [**50**Star][2m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) None
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
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
- [**49**Star][11m] [Py] [agustingianni/utilities](https://github.com/agustingianni/utilities) Uncategorized utilities
- [**47**Star][3y] [Py] [jjo-sec/idataco](https://github.com/jjo-sec/idataco) IDATACO IDA Pro Plugin
- [**45**Star][7y] [Py] [carlosgprado/milf](https://github.com/carlosgprado/milf) An IDA Pro swiss army knife (with a sexy name!)
    - [milf](https://github.com/carlosgprado/MILF/blob/master/milf.py) 辅助漏洞挖掘
- [**40**Star][6m] [Visual Basic] [dzzie/re_plugins](https://github.com/dzzie/re_plugins) misc reverse engineering plugins I have released over the years
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
- [**40**Star][2y] [Py] [mxmssh/idametrics](https://github.com/mxmssh/idametrics) IDA plugin for software complexity metrics assessment
- [**40**Star][4y] [C++] [nihilus/guid-finder](https://github.com/nihilus/guid-finder) None
- [**38**Star][2y] [Py] [saelo/ida_scripts](https://github.com/saelo/ida_scripts) Collection of IDA scripts
    - [kernelcache](https://github.com/saelo/ida_scripts/blob/master/kernelcache.py) 识别并重命名iOS kernelcache函数stub。ARM64 Only
    - [ssdt](https://github.com/saelo/ida_scripts/blob/master/ssdt.py) 解析Windows内核中的syscall表
- [**34**Star][4y] [Py] [madsc13ntist/idapython](https://github.com/madsc13ntist/idapython) My collection of IDAPython scripts.
- [**32**Star][5y] [Py] [iphelix/ida-pomidor](https://github.com/iphelix/ida-pomidor) IDA Pomidor is a plugin for Hex-Ray's IDA Pro disassembler that will help you retain concentration and productivity during long reversing sessions.
- [**28**Star][5m] [Py] [enovella/re-scripts](https://github.com/enovella/re-scripts) IDA, Ghidra and Radare2 scripts. Also Android scripts to make your life easier.
- [**28**Star][1y] [Py] [xyzz/vita-ida-physdump](https://github.com/xyzz/vita-ida-physdump) None
- [**27**Star][1y] [Py] [daniel_plohmann/simplifire.idascope](https://bitbucket.org/daniel_plohmann/simplifire.idascope) None
- [**26**Star][5y] [Py] [bastkerg/recomp](https://github.com/bastkerg/recomp) IDA recompiler
- [**26**Star][7m] [C++] [offlinej/ida-rpc](https://github.com/offlinej/ida-rpc) Discord rich presence plugin for IDA Pro 7.0
- [**25**Star][3y] [Py] [zyantific/continuum](https://github.com/zyantific/continuum) Plugin adding multi-binary project support to IDA Pro (WIP)
- [**23**Star][9m] [C++] [trojancyborg/ida_jni_rename](https://github.com/trojancyborg/ida_jni_rename) IDA JNI调用重命名
- [**22**Star][5y] [Py] [nihilus/idascope](https://github.com/nihilus/idascope) None
- [**22**Star][4y] [Py] [onethawt/idapyscripts](https://github.com/onethawt/idapyscripts) Collection of my IDAPython scripts
    - [DataXrefCounter ](https://github.com/onethawt/idapyscripts/blob/master/dataxrefcounter.py) 枚举指定区段的所有交叉引用，计算使用频率
- [**22**Star][3y] [C++] [patois/idaplugins](https://github.com/patois/idaplugins) Random IDA scripts, plugins, example code (some of it may be old and not working anymore)
- [**21**Star][2m] [Py] [nlitsme/idascripts](https://github.com/nlitsme/idascripts) IDApro idc and idapython script collection
- [**21**Star][1m] [Py] [rceninja/re-scripts](https://github.com/rceninja/re-scripts) None
    - [Hyperv-Scripts](https://github.com/rceninja/re-scripts/tree/master/scripts/Hyperv-Scripts) 
    - [IA32-MSR-Decoder](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-MSR-Decoder) 查找并解码所有的MSR码
    - [IA32-VMX-Helper](https://github.com/rceninja/re-scripts/tree/master/scripts/IA32-VMX-Helper) 查找并解码所有的MSR/VMCS码
- [**20**Star][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) ida python scripts
- [**20**Star][2y] [C#] [zoebear/radia](https://github.com/zoebear/radia) Radia is a tool designed to create an interactive and immerse environment to visualize code, and to augment the task of reverse engineering binaries. The tool takes decompiled binaries extracted through IDA Pro, and visualizes the call graph in 3D space as a force directed graph. Radia tags functions that could be potential problems, as well as …
- [**20**Star][3y] [Py] [ztrix/idascript](https://github.com/ztrix/idascript) Full functional idascript with stdin/stdout handled
- [**20**Star][1y] [Py] [hyuunnn/ida_python_scripts](https://github.com/hyuunnn/ida_python_scripts) ida python scripts
- [**20**Star][25d] [Py] [mephi42/ida-kallsyms](https://github.com/mephi42/ida-kallsyms) None
- [**19**Star][8m] [Py] [yellowbyte/reverse-engineering-playground](https://github.com/yellowbyte/reverse-engineering-playground) Scripts I made to aid me in everyday reversing or just for fun...
- [**18**Star][1y] [Py] [a1ext/ida-embed-arch-disasm](https://github.com/a1ext/ida-embed-arch-disasm) Allows IDA PRO to disassemble x86-64 code (WOW64) in 32-bit database
- [**17**Star][1y] [Py] [honeybadger1613/etm_displayer](https://github.com/honeybadger1613/etm_displayer) IDA Pro плагин для отображения результата Coresight ETM трассировки perf'а
- [**16**Star][4y] [fabi/idacsharp](https://github.com/fabi/idacsharp) C# 'Scripts' for IDA 6.6+ based on
- [**15**Star][7m] [CMake] [google/idaidle](https://github.com/google/idaidle) A plugin for the commercial IDA Pro disassembler that warns users if they leave their instance idling for too long.
- [**14**Star][4y] [C++] [nihilus/fast_idb2sig_and_loadmap_ida_plugins](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins) None
    - [LoadMap](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/tree/master/LoadMap) 
    - [idb2sig](https://github.com/nihilus/fast_idb2sig_and_loadmap_ida_plugins/blob/master/idb2sig/ReadMe.txt) 
- [**13**Star][2y] [Py] [cisco-talos/pdata_check](https://github.com/cisco-talos/pdata_check) None
- [**13**Star][11m] [C++] [nihilus/graphslick](https://github.com/nihilus/graphslick) IDA Plugin - GraphSlick
- [**13**Star][1y] [Py] [cxm95/ida_wrapper](https://github.com/cxm95/ida_wrapper) An IDA_Wrapper for linux, shipped with an Function Identifier. It works well with Driller on static linked binaries.
- [**12**Star][1y] [Assembly] [gabrielravier/cave-story-decompilation](https://github.com/gabrielravier/cave-story-decompilation) Decompilation of Cave Story. Made with IDA Pro
- [**11**Star][2y] [Py] [0xddaa/iddaa](https://github.com/0xddaa/iddaa) idapython scripts
- [**11**Star][5y] [Py] [dshikashio/idarest](https://github.com/dshikashio/idarest) Expose some basic IDA Pro interactions through a REST API for JSONP
- [**11**Star][9m] [C++] [ecx86/ida7-supportlib](https://github.com/ecx86/ida7-supportlib) IDA-SupportLib library by sirmabus, ported to IDA 7
- [**10**Star][4y] [C++] [revel8n/spu3dbg](https://github.com/revel8n/spu3dbg) Ida Pro plugin that supports debugging with the anergistic spu emulator
- [**9**Star][4y] [Py] [nfarrar/ida-colorschemes](https://github.com/nfarrar/ida-colorschemes) A .clr colorscheme generator for IDA Pro 6.4+.
- [**9**Star][5y] [Ruby] [rogwfu/plympton](https://github.com/rogwfu/plympton) Library to work with yaml exported IDA Pro information and run statistics
- [**9**Star][8m] [Py] [0xcpu/relieve](https://github.com/0xcpu/relieve) RE scripts, snippets (IDA, lief, gdb, etc.)
- [**8**Star][5y] [Py] [daniel_plohmann/idapatchwork](https://bitbucket.org/daniel_plohmann/idapatchwork) None
- [**8**Star][2y] [C++] [ecx86/ida7-segmentselect](https://github.com/ecx86/ida7-segmentselect) IDA-SegmentSelect library by sirmabus, ported to IDA 7
- [**8**Star][9d] [Py] [lanhikari22/gba-ida-pseudo-terminal](https://github.com/lanhikari22/gba-ida-pseudo-terminal) IDAPython tools to aid with analysis, disassembly and data extraction using IDA python commands, tailored for the GBA architecture at some parts
- [**8**Star][13d] [C++] [nlitsme/idcinternals](https://github.com/nlitsme/idcinternals) IDA plugin investigating the internal representation of IDC scripts
- [**8**Star][3y] [Py] [pwnslinger/ibt](https://github.com/pwnslinger/ibt) IDA Pro Back Tracer - Initial project toward automatic customized protocols structure extraction
- [**8**Star][2y] [C++] [shazar14/idadump](https://github.com/shazar14/idadump) An IDA Pro script to verify binaries found in a sample and write them to disk
- [**7**Star][2y] [Py] [swackhamer/ida_scripts](https://github.com/swackhamer/ida_scripts) IDA Python scripts
- [**7**Star][9m] [Py] [techbliss/ida_pro_http_ip_geolocator](https://github.com/techbliss/ida_pro_http_ip_geolocator) Google maps http and ip lookup for ida pro
- [**7**Star][5y] [Py] [techbliss/processor-changer](https://github.com/techbliss/processor-changer) Tool to change processor inside ida
- [**7**Star][1y] [C++] [tenable/mida](https://github.com/tenable/mida) None
- [**6**Star][2y] [CMake] [elemecca/cmake-ida](https://github.com/elemecca/cmake-ida) Build IDA Pro modules with CMake
- [**6**Star][2y] [Py] [fireundubh/ida7-alleycat](https://github.com/fireundubh/ida7-alleycat) Alleycat plugin by devttys0, ported to IDA 7
- [**6**Star][8m] [Py] [geosn0w/dumpanywhere64](https://github.com/geosn0w/dumpanywhere64) An IDA (Interactive Disassembler) script that can save a chunk of binary from an address.
- [**6**Star][1y] [C++] [ecx86/ida7-hexrays-invertif](https://github.com/ecx86/ida7-hexrays-invertif) Hex-Rays Invert if statement plugin for IDA 7.0
- [**5**Star][3y] [Py] [andreafioraldi/idavshelp](https://github.com/andreafioraldi/idavshelp) IDAPython plugin to integrate Visual Studio Help Viewer in IDA Pro >= 6.8
- [**5**Star][4m] [Py] [fdiskyou/ida-plugins](https://github.com/fdiskyou/ida-plugins) Dirty IDA scripts dump.
    - [banned_functions](https://github.com/fdiskyou/ida-plugins/blob/master/banned_functions.py) 
- [**5**Star][1y] [C++] [lab313ru/m68k_fixer](https://github.com/lab313ru/m68k_fixer) IDA Pro plugin fixer for m68k
- [**5**Star][5y] [C#] [npetrovski/ida-smartpatcher](https://github.com/npetrovski/ida-smartpatcher) IDA apply patch GUI
- [**5**Star][4y] [Py] [tmr232/tarkus](https://github.com/tmr232/tarkus) Plugin Manager for IDA Pro
- [**4**Star][1m] [Py] [gitmirar/idaextapi](https://github.com/gitmirar/idaextapi) IDA API utlitites
- [**4**Star][3y] [Py] [hustlelabs/joseph](https://github.com/hustlelabs/joseph) IDA Viewer Plugins
- [**4**Star][1y] [savagedd/samp-server-idb](https://github.com/savagedd/samp-server-idb) None
- [**4**Star][1m] [Py] [spigwitmer/golang_struct_builder](https://github.com/spigwitmer/golang_struct_builder) IDA 7.0+ script that auto-generates structs and interfaces from runtime metadata found in golang binaries
- [**3**Star][9m] [Py] [gdataadvancedanalytics/ida-python](https://github.com/gdataadvancedanalytics/ida-python) None
- [**3**Star][2y] [Py] [ypcrts/ida-pro-segments](https://github.com/ypcrts/ida-pro-segments) It's very hard to load multiple files in the IDA GUI without it exploding. This makes it easy.
- [**3**Star][1y] [abarbatei/ida-utils](https://github.com/abarbatei/ida-utils) links, information and helper scripts for IDA Pro
- [**2**Star][2y] [C++] [ecx86/ida7-oggplayer](https://github.com/ecx86/ida7-oggplayer) IDA-OggPlayer library by sirmabus, ported to IDA 7
- [**2**Star][2y] [Py] [mayl8822/ida](https://github.com/mayl8822/ida) Some useful ida script plugin
- [**2**Star][5y] [C++] [nihilus/ida-x86emu](https://github.com/nihilus/ida-x86emu) None
- [**2**Star][4y] [Py] [nihilus/idapatchwork](https://github.com/nihilus/idapatchwork) 
- [**2**Star][2y] [Py] [sbouber/idaplugins](https://github.com/sbouber/idaplugins) None
- [**2**Star][1m] [Py] [psxvoid/idapython-debugging-dynamic-enrichment](https://github.com/psxvoid/idapython-debugging-dynamic-enrichment) None
- [**1**Star][2y] [Py] [andreafioraldi/idamsdnhelp](https://github.com/andreafioraldi/idamsdnhelp) IdaPython plugin to open MSDN Help Search page
- [**1**Star][1y] [Py] [farzonl/idapropluginlab4](https://github.com/farzonl/idapropluginlab4) An ida pro plugin that tracks def use chains of a given x86 binary.
- [**1**Star][2m] [Py] [voidsec/ida-helpers](https://github.com/voidsec/ida-helpers) Collection of IDA helpers


***


## <a id="fb4f0c061a72fc38656691746e7c45ce"></a>Structure&&Class


### <a id="fa5ede9a4f58d4efd98585d3158be4fb"></a>NoCategory


- [**924**Star][13d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) Binary code static analyser, with IDA integration. Performs value and taint analysis, type reconstruction, use-after-free and double-free detection
    - Also In Section: [Tools/TaintAnalysis&&SymbolicExecution](#34ac84853604a7741c61670f2a075d20) |
- [**649**Star][4m] [Py] [igogo-x86/hexrayspytools](https://github.com/igogo-x86/hexrayspytools) IDA Pro plugin which improves work with HexRays decompiler and helps in process of reconstruction structures and classes
- [**168**Star][12m] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches.
    - Also In Section: [Tools/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/kernelCache](#82d0fa2d6934ce29794a651513934384) |
- [**138**Star][4y] [C++] [nihilus/hexrays_tools](https://github.com/nihilus/hexrays_tools) None
- [**103**Star][2m] [Py] [lucasg/findrpc](https://github.com/lucasg/findrpc) Idapython script to carve binary for internal RPC structures
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to search strings in a specified range of addresses and map it to a C struct
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


### <a id="4900b1626f10791748b20630af6d6123"></a>C++Class&&VirtualTable


- [**595**Star][2m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for creating automatic C++ virtual tables in IDA Pro
    - Also In Section: [Tools/Debug&&DynamicData/DebuggerData](#b31acf6c84a9506066d497af4e702bf5) |
        <details>
        <summary>View Details</summary>


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


- [**168**Star][9m] [C++] [ecx86/classinformer-ida7](https://github.com/ecx86/classinformer-ida7) ClassInformer backported for IDA Pro 7.0
- [**128**Star][2y] [Py] [nccgroup/susanrtti](https://github.com/nccgroup/SusanRTTI) Another RTTI Parsing IDA plugin
- [**91**Star][1y] [C++] [rub-syssec/marx](https://github.com/rub-syssec/marx) Uncovering Class Hierarchies in C++ Programs
    - [IDA导出](https://github.com/rub-syssec/marx/blob/master/ida_export/export.py) 
    - [IDA导入插件](https://github.com/rub-syssec/marx/tree/master/ida_import) 
    - [核心代码](https://github.com/rub-syssec/marx/tree/master/src) 
- [**68**Star][7y] [C] [nektra/vtbl-ida-pro-plugin](https://github.com/nektra/vtbl-ida-pro-plugin) Identifying Virtual Table Functions using VTBL IDA Pro Plugin + Deviare Hooking Engine
- [**35**Star][5y] [C++] [nihilus/ida_classinformer](https://github.com/nihilus/ida_classinformer) IDA ClassInformer PlugIn
- [**32**Star][2y] [Py] [krystalgamer/dec2struct](https://github.com/krystalgamer/dec2struct) Python plugin to easily setup vtables in IDA using declaration files
- [**16**Star][2y] [C++] [mwl4/ida_gcc_rtti](https://github.com/mwl4/ida_gcc_rtti) Class informer plugin for IDA which supports parsing GCC RTTI




***


## <a id="a7dac37cd93b8bb42c7d6aedccb751b3"></a>Collection


- [**1732**Star][1m] [onethawt/idaplugins-list](https://github.com/onethawt/idaplugins-list) A list of IDA Plugins
- [**356**Star][8m] [fr0gger/awesome-ida-x64-olly-plugin](https://github.com/fr0gger/awesome-ida-x64-olly-plugin) A curated list of IDA x64DBG and OllyDBG plugins.
- [**10**Star][1y] [Py] [ecx86/ida-scripts](https://github.com/ecx86/ida-scripts) Collection of IDA Pro/Hex-Rays configs, scripts, and plugins


***


## <a id="fabf03b862a776bbd8bcc4574943a65a"></a>Skin&&Theme


- [**712**Star][5m] [Py] [zyantific/idaskins](https://github.com/zyantific/idaskins) Advanced skinning plugin for IDA Pro
- [**257**Star][7y] [eugeneching/ida-consonance](https://github.com/eugeneching/ida-consonance) Consonance, a dark color scheme for IDA.
- [**103**Star][5m] [CSS] [0xitx/ida_nightfall](https://github.com/0xitx/ida_nightfall) A dark color theme for IDA Pro
- [**58**Star][7y] [gynophage/solarized_ida](https://github.com/gynophage/solarized_ida) Solarized Dark IDA Pro Theme
- [**10**Star][7y] [Py] [luismiras/ida-color-scripts](https://github.com/luismiras/ida-color-scripts) IDA Color Theme Scripts
- [**8**Star][2y] [CSS] [gbps/x64dbg-consonance-theme](https://github.com/gbps/x64dbg-consonance-theme) A dark x64dbg color theme based on IDA Consonance
- [**6**Star][5y] [Py] [techbliss/ida-styler](https://github.com/techbliss/ida-styler) Small Plugin to change the style off Ida Pro
- [**3**Star][1m] [rootbsd/ida_pro_zinzolin_theme](https://github.com/rootbsd/ida_pro_zinzolin_theme) None
- [**1**Star][12m] [C] [albertzsigovits/idc-dark](https://github.com/albertzsigovits/idc-dark) A dark-mode color scheme for Hex-Rays IDA using idc


***


## <a id="a8f5db3ab4bc7bc3d6ca772b3b9b0b1e"></a>Firmware&&EmbedDevice


- [**5105**Star][13d] [Py] [refirmlabs/binwalk](https://github.com/ReFirmLabs/binwalk) Firmware Analysis Tool
    - [IDA插件](https://github.com/ReFirmLabs/binwalk/tree/master/src/scripts) 
    - [binwalk](https://github.com/ReFirmLabs/binwalk/tree/master/src/binwalk) 
- [**483**Star][3m] [Py] [maddiestone/idapythonembeddedtoolkit](https://github.com/maddiestone/idapythonembeddedtoolkit) IDA Python Embedded Toolkit -- IDAPython scripts for automating analysis of firmware of embedded devices
- [**173**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) A collection of IDAPython modules made with
    - Also In Section: [Tools/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/NoCategory](#8530752bacfb388f3726555dc121cb1a) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**90**Star][16d] [Py] [pagalaxylab/vxhunter](https://github.com/PAGalaxyLab/vxhunter) ToolSet for VxWorks Based Embedded Device Analyses
    - [R2](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_r2_py2.py) 
    - [IDA插件](https://github.com/PAGalaxyLab/vxhunter/blob/master/firmware_tools/vxhunter_ida.py) 
    - [Ghidra插件](https://github.com/PAGalaxyLab/vxhunter/tree/master/firmware_tools/ghidra) 


***


## <a id="02088f4884be6c9effb0f1e9a3795e58"></a>Signature(FLIRT...)&&Diff&&Match


### <a id="cf04b98ea9da0056c055e2050da980c1"></a>NoCategory


- [**416**Star][22d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) The Kam1n0 Assembly Analysis Platform
    - Also In Section: [Tools/PartOfOtherTool](#83de90385d03ac8ef27360bfcdc1ab48) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**147**Star][1y] [C++] [ajkhoury/sigmaker-x64](https://github.com/ajkhoury/SigMaker-x64) IDA Pro 7.0 compatible SigMaker plugin
- [**128**Star][1y] [Py] [cisco-talos/bass](https://github.com/cisco-talos/bass) BASS - BASS Automated Signature Synthesizer
- [**71**Star][4y] [Py] [icewall/bindifffilter](https://github.com/icewall/bindifffilter) IDA Pro plugin making easier work on BinDiff results
- [**70**Star][5y] [Py] [arvinddoraiswamy/slid](https://github.com/arvinddoraiswamy/slid) Statically linked Library detector
- [**50**Star][1m] [Py] [vrtadmin/first-plugin-ida](https://github.com/vrtadmin/first-plugin-ida) None
- [**45**Star][1y] [Py] [l4ys/idasignsrch](https://github.com/l4ys/idasignsrch) IDA_Signsrch in Python
- [**33**Star][3y] [Py] [g4hsean/binauthor](https://github.com/g4hsean/binauthor) None
- [**31**Star][1y] [Py] [cisco-talos/casc](https://github.com/cisco-talos/casc) None
- [**25**Star][2y] [LLVM] [syreal17/cardinal](https://github.com/syreal17/cardinal) Similarity Analysis to Defeat Malware Compiler Variations
- [**23**Star][4m] [Py] [xorpd/fcatalog_server](https://github.com/xorpd/fcatalog_server) Functions Catalog
- [**21**Star][3y] [Py] [xorpd/fcatalog_client](https://github.com/xorpd/fcatalog_client) fcatalog idapython client
- [**18**Star][5y] [Py] [zaironne/snippetdetector](https://github.com/zaironne/snippetdetector) IDA Python scripts project for snippets detection
- [**16**Star][8y] [C++] [alexander-pick/idb2pat](https://github.com/alexander-pick/idb2pat) idb2pat plugin, fixed to work with IDA 6.2
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA PRO signature files that can be used in reversing the iPhone baseband. On an iPhone 4 firmware can pickup upto 800 functions when all the sigs applied.
    - Also In Section: [Tools/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/NoCategory](#8530752bacfb388f3726555dc121cb1a) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) IDA scripts which compare Linux and Windows binaries to automatically rename unnamed Windows functions.
    - Also In Section: [Tools/Function/Rename&&Prefix&&Tag](#73813456eeb8212fd45e0ea347bec349) |
- [**0**Star][1y] [Py] [gh0st3rs/idaprotosync](https://github.com/gh0st3rs/idaprotosync) IDAPython plugin for identifies functions prototypes between two or more IDBs


### <a id="19360afa4287236abe47166154bc1ece"></a>FLIRT


#### <a id="1c9d8dfef3c651480661f98418c49197"></a>FLIRTSignatureCollection


- [**589**Star][8d] [Max] [maktm/flirtdb](https://github.com/Maktm/FLIRTDB) A community driven collection of IDA FLIRT signature files
- [**303**Star][4m] [push0ebp/sig-database](https://github.com/push0ebp/sig-database) IDA FLIRT Signature Database
- [**5**Star][8m] [cloudwindby/ida-pro-sig](https://github.com/cloudwindby/ida-pro-sig) IDA PRO FLIRT signature files MSVC2017的sig文件


#### <a id="a9a63d23d32c6c789ca4d2e146c9b6d0"></a>FLIRTSignatureGenerate


- [**58**Star][10m] [Py] [push0ebp/allirt](https://github.com/push0ebp/allirt) Tool that converts All of libc to signatures for IDA Pro FLIRT Plugin. and utility make sig with FLAIR easily
- [**42**Star][7m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/Ghidra](#c7066b0c388cd447e980bf0eb38f39ab) |




### <a id="161e5a3437461dc8959cc923e6a18ef7"></a>Diff&&Match


- [**1525**Star][20d] [Py] [joxeankoret/diaphora](https://github.com/joxeankoret/diaphora) Diaphora, the most advanced Free and Open Source program diffing tool.
- [**353**Star][3m] [Py] [checkpointsw/karta](https://github.com/checkpointsw/karta) Karta - source code assisted fast binary matching plugin for IDA
- [**328**Star][11m] [Py] [joxeankoret/pigaios](https://github.com/joxeankoret/pigaios) A tool for matching and diffing source codes directly against binaries.
- [**136**Star][12m] [Py] [nirizr/rematch](https://github.com/nirizr/rematch) REmatch, a complete binary diffing framework that is free and strives to be open source and community driven.
- [**94**Star][6m] [Visual Basic] [dzzie/idacompare](https://github.com/dzzie/idacompare) IDA disassembly level diffing tool, - read more->
- [**74**Star][4y] [C] [nihilus/ida_signsrch](https://github.com/nihilus/ida_signsrch) IDA Signsrch
- [**72**Star][5y] [Py] [binsigma/binsourcerer](https://github.com/binsigma/binsourcerer) BinSourcerer
- [**71**Star][3y] [vrtadmin/first](https://github.com/vrtadmin/first) None
- [**52**Star][5y] [C++] [filcab/patchdiff2](https://github.com/filcab/patchdiff2) IDA binary differ. Since code.google.com/p/patchdiff2/ seemed abandoned, I did the obvious thing…
- [**14**Star][3y] [Py] [0x00ach/idadiff](https://github.com/0x00ach/idadiff) IDAPython script in order to auto-rename subs
- [**14**Star][5y] [C++] [binsigma/binclone](https://github.com/binsigma/binclone) None


### <a id="46c9dfc585ae59fe5e6f7ddf542fb31a"></a>Yara


- [**424**Star][23d] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [Tools/encrypt&&decrypt](#06d2caabef97cf663bd29af2b1fe270c) |
- [**92**Star][29d] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/Hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
    - [IDA插件](https://github.com/hy00un/hyara/tree/master/IDA%20Plugin) 
    - [BinaryNinja插件](https://github.com/hy00un/hyara/tree/master/BinaryNinja%20Plugin) 
- [**92**Star][29d] [Py] [hyuunnn/hyara](https://github.com/hyuunnn/hyara) Yara rule making tool (IDA Pro & Binary Ninja Plugin)
- [**81**Star][1y] [Py] [oalabs/findyara](https://github.com/oalabs/findyara) IDA python plugin to scan binary with Yara rules
- [**16**Star][10m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) IDA Processor for Compiled YARA Rules
    - Also In Section: [Tools/SpecificTarget/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**14**Star][1y] [Py] [alexander-hanel/ida_yara](https://github.com/alexander-hanel/ida_yara) A python script that can be used to scan data within in an IDB using Yara.
- [**14**Star][1y] [Py] [souhailhammou/idaray-plugin](https://github.com/souhailhammou/idaray-plugin) IDARay is an IDA Pro plugin that matches the database against multiple YARA files which themselves may contain multiple rules.




***


## <a id="5e91b280aab7f242cbc37d64ddbff82f"></a>IDB


- [**312**Star][5m] [Py] [williballenthin/python-idb](https://github.com/williballenthin/python-idb) Pure Python parser and analyzer for IDA Pro database files (.idb).
- [**144**Star][10d] [Py] [nccgroup/idahunt](https://github.com/nccgroup/idahunt) idahunt is a framework to analyze binaries with IDA Pro and hunt for things in IDA Pro
- [**84**Star][4m] [C++] [nlitsme/idbutil](https://github.com/nlitsme/idbutil) Library and tool for reading IDApro databases.
- [**78**Star][2m] [Py] [nlitsme/pyidbutil](https://github.com/nlitsme/pyidbutil) A python library for reading IDA pro databases.
- [**18**Star][1y] [Py] [kkhaike/tinyidb](https://github.com/kkhaike/tinyidb) Some python scripts are used to export userdata from huge idb(ida's database)，ida 7.0 support only
- [**0**Star][4y] [C] [hugues92/idaextrapassplugin](https://github.com/hugues92/idaextrapassplugin) None


***


## <a id="206ca17fc949b8e0ae62731d9bb244cb"></a>CollaborativeRE


- [**504**Star][10m] [Py] [idarlingteam/idarling](https://github.com/IDArlingTeam/IDArling) Collaborative Reverse Engineering plugin for IDA Pro & Hex-Rays
- [**257**Star][1y] [C++] [dga-mi-ssi/yaco](https://github.com/dga-mi-ssi/yaco) YaCo is an Hex-Rays IDA plugin. When enabled, multiple users can work simultaneously on the same binary. Any modification done by any user is synchronized through git version control.
- [**88**Star][5y] [Py] [cubicalabs/idasynergy](https://github.com/cubicalabs/idasynergy) A combination of an IDAPython Plugin and a control version system that result in a new reverse engineering collaborative addon for IDA Pro. By
- [**71**Star][17d] [C++] [cseagle/collabreate](https://github.com/cseagle/collabreate) Collaborative reverse engineering plugin for IDA Pro. Latest version, including IDA 7.0 support, is not back ward compatible with earlier versions. Substantial changes have been made to the protocol and database.
- [**4**Star][2y] [Py] [argussecurity/psida](https://bitbucket.org/socialauth/login/atlassianid/?next=%2Fargussecurity%2Fpsida) None


***


## <a id="f7d311685152ac005cfce5753c006e4b"></a>SyncWithDebugger


- [**448**Star][18d] [C] [bootleg/ret-sync](https://github.com/bootleg/ret-sync) ret-sync is a set of plugins that helps to synchronize a debugging session (WinDbg/GDB/LLDB/OllyDbg2/x64dbg) with IDA/Ghidra disassemblers.
    - [GDB插件](https://github.com/bootleg/ret-sync/tree/master/ext_gdb) 
    - [Ghidra插件](https://github.com/bootleg/ret-sync/tree/master/ext_ghidra) 
    - [IDA插件](https://github.com/bootleg/ret-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/bootleg/ret-sync/tree/master/ext_lldb) 
    - [OD](https://github.com/bootleg/ret-sync/tree/master/ext_olly1) 
    - [OD2](https://github.com/bootleg/ret-sync/tree/master/ext_olly2) 
    - [WinDgb](https://github.com/bootleg/ret-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/bootleg/ret-sync/tree/master/ext_x64dbg) 
- [**285**Star][9m] [C] [a1ext/labeless](https://github.com/a1ext/labeless) Labeless is a multipurpose IDA Pro plugin system for labels/comments synchronization with a debugger backend, with complex memory dumping and interactive Python scripting capabilities.
    - [IDA插件](https://github.com/a1ext/labeless/tree/master/labeless_ida) 
    - [OD](https://github.com/a1ext/labeless/tree/master/labeless_olly) 
    - [OD2](https://github.com/a1ext/labeless/tree/master/labeless_olly2) 
    - [x64dbg](https://github.com/a1ext/labeless/tree/master/labeless_x64dbg) 
- [**168**Star][11m] [Py] [andreafioraldi/idangr](https://github.com/andreafioraldi/idangr) Use angr in the IDA Pro debugger generating a state from the current debug session
- [**128**Star][2y] [Py] [comsecuris/gdbida](https://github.com/comsecuris/gdbida) gdbida - a visual bridge between a GDB session and IDA Pro's disassembler
    - [IDA插件](https://github.com/comsecuris/gdbida/blob/master/ida_gdb_bridge.py) 
    - [GDB脚本](https://github.com/comsecuris/gdbida/blob/master/gdb_ida_bridge_client.py) 
- [**98**Star][4y] [C++] [quarkslab/qb-sync](https://github.com/quarkslab/qb-sync) qb-sync is an open source tool to add some helpful glue between IDA Pro and Windbg. Its core feature is to dynamically synchronize IDA's graph windows with Windbg's position.
    - [GDB插件](https://github.com/quarkslab/qb-sync/tree/master/ext_gdb) 
    - [IDA插件](https://github.com/quarkslab/qb-sync/tree/master/ext_ida) 
    - [LLDB](https://github.com/quarkslab/qb-sync/tree/master/ext_lldb) 
    - [OD2](https://github.com/quarkslab/qb-sync/tree/master/ext_olly2) 
    - [WinDbg](https://github.com/quarkslab/qb-sync/tree/master/ext_windbg/sync) 
    - [x64dbg](https://github.com/quarkslab/qb-sync/tree/master/ext_x64dbg) 
- [**43**Star][3m] [JS] [sinakarvandi/windbg2ida](https://github.com/sinakarvandi/windbg2ida) Windbg2ida lets you dump each step in Windbg then shows these steps in IDA
    - [Windbg脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/windbg2ida.js) JavaScript
    - [IDA脚本](https://github.com/sinakarvandi/windbg2ida/blob/master/IDAScript.py) 
- [**36**Star][9m] [Py] [anic/ida2pwntools](https://github.com/anic/ida2pwntools) a IDA 7.0 plugins that helps to attach process created by pwntools and debug pwn
- [**28**Star][1y] [Py] [iweizime/dbghider](https://github.com/iweizime/dbghider) An IDA plugin aims to hide debugger from processes
- [**17**Star][7y] [Py] [rmadair/windbg2ida](https://github.com/rmadair/windbg2ida) Import debugging traces from WinDBG into IDA. Color the graph, fill in the value of all the operands, etc.


***


## <a id="6fb7e41786c49cc3811305c520dfe9a1"></a>ImportExport&&SyncWithOtherTools


### <a id="8ad723b704b044e664970b11ce103c09"></a>NoCategory


- [**159**Star][27d] [Py] [x64dbg/x64dbgida](https://github.com/x64dbg/x64dbgida) Official x64dbg plugin for IDA Pro.
- [**143**Star][28d] [C++] [alschwalm/dwarfexport](https://github.com/alschwalm/dwarfexport) Export dwarf debug information from IDA Pro
- [**95**Star][2y] [Py] [robindavid/idasec](https://github.com/robindavid/idasec) IDA plugin for reverse-engineering and dynamic interactions with the Binsec platform
- [**67**Star][11m] [Py] [lucasg/idamagnum](https://github.com/lucasg/idamagnum) idamagnum is a plugin for integrating MagnumDB requests within IDA
- [**58**Star][8d] [Py] [binaryanalysisplatform/bap-ida-python](https://github.com/binaryanalysisplatform/bap-ida-python) integration with IDA
- [**35**Star][5y] [Py] [siberas/ida2sym](https://github.com/siberas/ida2sym) IDAScript to create Symbol file which can be loaded in WinDbg via AddSyntheticSymbol
- [**29**Star][5y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [Tools/SpecificTarget/PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**28**Star][4m] [C++] [thalium/idatag](https://github.com/thalium/idatag) IDA plugin to explore and browse tags
- [**19**Star][2y] [Py] [brandon-everhart/angryida](https://github.com/brandon-everhart/angryida) Python based angr plug in for IDA Pro.
- [**16**Star][4y] [C++] [m417z/mapimp](https://github.com/m417z/mapimp) This is an OllyDbg plugin which will help you to import map files exported by IDA, Dede, IDR, Microsoft and Borland linkers.
- [**16**Star][4y] [Py] [danielmgmi/virusbattle-ida-plugin](https://github.com/danielmgmi/virusbattle-ida-plugin) The plugin is an integration of Virus Battle API to the well known IDA Disassembler.
- [**8**Star][7y] [C++] [patois/madnes](https://github.com/patois/madnes) IDA plugin to export symbols and names from IDA db so they can be loaded into FCEUXD SP
- [**3**Star][1y] [Py] [r00tus3r/differential_debugging](https://github.com/r00tus3r/differential_debugging) Differential debugging using IDA Python and GDB


### <a id="c7066b0c388cd447e980bf0eb38f39ab"></a>Ghidra


- [**288**Star][3m] [Py] [cisco-talos/ghida](https://github.com/cisco-talos/ghida) None
- [**235**Star][8m] [Py] [daenerys-sre/source](https://github.com/daenerys-sre/source) Daenerys: A framework for interoperability between IDA and Ghidra
- [**85**Star][3m] [Py] [cisco-talos/ghidraaas](https://github.com/cisco-talos/ghidraaas) None
- [**47**Star][1m] [Py] [utkonos/lst2x64dbg](https://github.com/utkonos/lst2x64dbg) Extract labels from IDA .lst or Ghidra .csv file and export x64dbg database.
- [**42**Star][7m] [Py] [nwmonster/applysig](https://github.com/nwmonster/applysig) Apply IDA FLIRT signatures for Ghidra
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/FLIRT/FLIRTSignatureGenerate](#a9a63d23d32c6c789ca4d2e146c9b6d0) |


### <a id="11139e7d6db4c1cef22718868f29fe12"></a>BinNavi


- [**378**Star][14d] [C++] [google/binexport](https://github.com/google/binexport) Export disassemblies into Protocol Buffers and to BinNavi databases
- [**213**Star][3y] [PLpgSQL] [cseagle/freedom](https://github.com/cseagle/freedom) capstone based disassembler for extracting to binnavi
- [**25**Star][7y] [Py] [tosanjay/bopfunctionrecognition](https://github.com/tosanjay/bopfunctionrecognition) This python/jython script is used as plugin to BinNavi tool to analyze a x86 binanry file to find buffer overflow prone functions. Such functions are important for vulnerability analysis.


### <a id="d1ff64bee76f6749aef6100d72bfbe3a"></a>BinaryNinja


- [**67**Star][7m] [Py] [lunixbochs/revsync](https://github.com/lunixbochs/revsync) realtime cross-tool collaborative reverse engineering
- [**60**Star][5m] [Py] [zznop/bnida](https://github.com/zznop/bnida) Suite of plugins that provide the ability to transfer analysis data between Binary Ninja and IDA
    - [ida_export](https://github.com/zznop/bnida/blob/master/ida/ida_export.py) 将数据从IDA中导入
    - [ida_import](https://github.com/zznop/bnida/blob/master/ida/ida_import.py) 将数据导入到IDA
    - [binja_export](https://github.com/zznop/bnida/blob/master/binja_export.py) 将数据从BinaryNinja中导出
    - [binja_import](https://github.com/zznop/bnida/blob/master/binja_import.py) 将数据导入到BinaryNinja
- [**14**Star][5m] [Py] [cryptogenic/idc_importer](https://github.com/cryptogenic/idc_importer) A Binary Ninja plugin for importing IDC database dumps from IDA.


### <a id="21ed198ae5a974877d7a635a4b039ae3"></a>Radare2


- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Tools/Function/NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**123**Star][25d] [Py] [radare/radare2ida](https://github.com/radare/radare2ida) Tools, documentation and scripts to move projects from IDA to R2 and viceversa


### <a id="a1cf7f7f849b4ca2101bd31449c2a0fd"></a>Frida


- [**129**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) FRAPL Framework
    - Also In Section: [Tools/Debug&&DynamicData/DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**81**Star][5y] [Py] [techbliss/frida_for_ida_pro](https://github.com/techbliss/frida_for_ida_pro) Frida PluginFor Ida Pro
- [**50**Star][2m] [Py] [lich4/personal_script](https://github.com/lich4/personal_script) None
    - Also In Section: [Tools/NoCategory](#c39a6d8598dde6abfeef43faf931beb5) |
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


- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [Tools/Debug&&DynamicData/DBIData](#0fbd352f703b507853c610a664f024d1) |[Tools/Vul/NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**43**Star][3y] [Batchfile] [maldiohead/idapin](https://github.com/maldiohead/idapin) plugin of ida with pin




***


## <a id="004c199e1dbf71769fbafcd8e58d1ead"></a>SpecificTarget


### <a id="5578c56ca09a5804433524047840980e"></a>NoCategory


- [**539**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) VMAttack PlugIn for IDA Pro
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**195**Star][4y] [Py] [f8left/decllvm](https://github.com/f8left/decllvm) 针对OLLVM的IDA分析插件
- [**117**Star][1y] [Py] [xerub/idastuff](https://github.com/xerub/idastuff) IDA Pro/Hexrays plugins
- [**93**Star][3m] [Py] [themadinventor/ida-xtensa](https://github.com/themadinventor/ida-xtensa) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266)
- [**81**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [Tools/Debug&&DynamicData/NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**74**Star][2m] [Py] [coldzer0/ida-for-delphi](https://github.com/coldzer0/ida-for-delphi) IDA Python Script to Get All function names from Event Constructor (VCL)
- [**59**Star][2y] [Py] [isra17/nrs](https://github.com/isra17/nrs) NSIS Reversing Suite with IDA Plugins
- [**54**Star][3m] [Py] [giantbranch/mipsaudit](https://github.com/giantbranch/mipsaudit) IDA MIPS静态扫描脚本，汇编审计辅助脚本
- [**53**Star][5m] [C++] [troybowman/dtxmsg](https://github.com/troybowman/dtxmsg) None
- [**47**Star][2y] [C++] [antid0tecom/aarch64_armv81extension](https://github.com/antid0tecom/aarch64_armv81extension) IDA AArch64 processor extender extension: Adding support for ARMv8.1 opcodes
- [**47**Star][8m] [C] [lab313ru/smd_ida_tools](https://github.com/lab313ru/smd_ida_tools) Special IDA Pro tools for the Sega Genesis/Megadrive romhackers
- [**33**Star][3y] [Py] [sam-b/windows_syscalls_dumper](https://github.com/sam-b/windows_syscalls_dumper) A dirty IDAPython script to dump windows system call number/name pairs as JSON
- [**23**Star][3y] [Py] [pfalcon/ida-xtensa2](https://github.com/pfalcon/ida-xtensa2) IDAPython plugin for Tensilica Xtensa (as seen in ESP8266), version 2
- [**21**Star][11m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [Tools/Function/Rename&&Prefix&&Tag](#73813456eeb8212fd45e0ea347bec349) |
- [**20**Star][5y] [Py] [digitalbond/ibal](https://github.com/digitalbond/ibal) None
- [**17**Star][2y] [C] [andywhittaker/idaproboschme7x](https://github.com/andywhittaker/idaproboschme7x) IDA Pro Bosch ME7x C16x Disassembler Helper
- [**16**Star][3y] [Py] [0xdeva/ida-cpu-risc-v](https://github.com/0xdeva/ida-cpu-risc-v) RISCV-V disassembler for IDA Pro
- [**15**Star][5y] [Py] [dolphin-emu/gcdsp-ida](https://github.com/dolphin-emu/gcdsp-ida) An IDA plugin for GC DSP reverse engineering
- [**11**Star][2y] [C++] [hyperiris/gekkops](https://github.com/hyperiris/gekkops) Nintendo GameCube Gekko CPU Extension plug-in for IDA Pro 5.2
- [**4**Star][3y] [Py] [neogeodev/idaneogeo](https://github.com/neogeodev/idaneogeo) NeoGeo binary loader & helper for the Interactive Disassembler
- [**2**Star][3m] [C] [extremlapin/glua_c_headers_for_ida](https://github.com/extremlapin/glua_c_headers_for_ida) Glua module C headers for IDA
- [**2**Star][4m] [Py] [lucienmp/idapro_m68k](https://github.com/lucienmp/idapro_m68k) Extends existing support in IDA for the m68k by adding gdb step-over and type information support
- [**0**Star][8m] [C] [0xd0cf11e/idcscripts](https://github.com/0xd0cf11e/idcscripts) Scripts used when analyzing files in IDA
    - [emotet-decode](https://github.com/0xd0cf11e/idcscripts/blob/master/emotet/emotet-decode.idc) 解码emotet
- [**0**Star][1m] [C++] [marakew/emuppc](https://github.com/marakew/emuppc) simple PowerPC emulator for unpack into IDAPro some PowerPC binary


### <a id="1b17ac638aaa09852966306760fda46b"></a>GoLang


- [**363**Star][8m] [Py] [sibears/idagolanghelper](https://github.com/sibears/idagolanghelper) Set of IDA Pro scripts for parsing GoLang types information stored in compiled binary
- [**285**Star][23d] [Py] [strazzere/golang_loader_assist](https://github.com/strazzere/golang_loader_assist) Making GO reversing easier in IDA Pro


### <a id="4c158ccc5aee04383755851844fdd137"></a>WindowsDriver


- [**303**Star][1y] [Py] [fsecurelabs/win_driver_plugin](https://github.com/FSecureLABS/win_driver_plugin) A tool to help when dealing with Windows IOCTL codes or reversing Windows drivers.
- [**216**Star][12m] [Py] [nccgroup/driverbuddy](https://github.com/nccgroup/driverbuddy) DriverBuddy is an IDA Python script to assist with the reverse engineering of Windows kernel drivers.
- [**73**Star][4y] [Py] [tandasat/winioctldecoder](https://github.com/tandasat/winioctldecoder) IDA Plugin which decodes Windows Device I/O control code into DeviceType, FunctionCode, AccessType and MethodType.
- [**23**Star][1y] [C] [ioactive/kmdf_re](https://github.com/ioactive/kmdf_re) Helper idapython code for reversing kmdf drivers


### <a id="315b1b8b41c67ae91b841fce1d4190b5"></a>PS3&&PS4


- [**68**Star][2m] [C] [aerosoul94/ida_gel](https://github.com/aerosoul94/ida_gel) A collection of IDA loaders for various game console ELF's. (PS3, PSVita, WiiU)
- [**55**Star][7y] [C++] [kakaroto/ps3ida](https://github.com/kakaroto/ps3ida) IDA scripts and plugins for PS3
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**29**Star][5y] [C++] [oct0xor/deci3dbg](https://github.com/oct0xor/deci3dbg) Ida Pro debugger module for Playstation 3
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/NoCategory](#8ad723b704b044e664970b11ce103c09) |


### <a id="cb59d84840e41330a7b5e275c0b81725"></a>Loader&Processor


- [**205**Star][1y] [Py] [fireeye/idawasm](https://github.com/fireeye/idawasm) IDA Pro loader and processor modules for WebAssembly
- [**158**Star][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [Tools/Android](#66052f824f5054aa0f70785a2389a478) |[Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
- [**155**Star][2y] [Py] [crytic/ida-evm](https://github.com/crytic/ida-evm) IDA Processor Module for the Ethereum Virtual Machine (EVM)
- [**138**Star][28d] [Py] [argp/iboot64helper](https://github.com/argp/iboot64helper) IDAPython loader to help with AArch64 iBoot, iBEC, and SecureROM reverse engineering
- [**127**Star][2y] [C] [gsmk/hexagon](https://github.com/gsmk/hexagon) IDA processor module for the hexagon (QDSP6) processor
- [**106**Star][1y] [pgarba/switchidaproloader](https://github.com/pgarba/switchidaproloader) Loader for IDA Pro to support the Nintendo Switch NRO binaries
- [**72**Star][2y] [Py] [embedi/meloader](https://github.com/embedi/meloader) Intel Management Engine firmware loader plugin for IDA
- [**54**Star][5m] [C++] [mefistotelis/ida-pro-loadmap](https://github.com/mefistotelis/ida-pro-loadmap) Plugin for IDA Pro disassembler which allows loading .map files.
- [**37**Star][11m] [C++] [patois/nesldr](https://github.com/patois/nesldr) Nintendo Entertainment System (NES) ROM loader module for IDA Pro
- [**35**Star][1y] [Py] [bnbdr/ida-bpf-processor](https://github.com/bnbdr/ida-bpf-processor) BPF Processor for IDA Python
- [**32**Star][5y] [Py] [0xebfe/3dsx-ida-pro-loader](https://github.com/0xebfe/3dsx-ida-pro-loader) IDA PRO Loader for 3DSX files
- [**32**Star][1y] [C++] [teammolecule/toshiba-mep-idp](https://github.com/TeamMolecule/toshiba-mep-idp) IDA Pro module for Toshiba MeP processors
- [**28**Star][4y] [C] [gdbinit/teloader](https://github.com/gdbinit/teloader) A TE executable format loader for IDA
- [**27**Star][3y] [Py] [w4kfu/ida_loader](https://github.com/w4kfu/ida_loader) Some loader module for IDA
- [**25**Star][2m] [Py] [ghassani/mclf-ida-loader](https://github.com/ghassani/mclf-ida-loader) An IDA file loader for Mobicore trustlet and driver binaries
- [**23**Star][1y] [C++] [balika011/belf](https://github.com/balika011/belf) Balika011's PlayStation 4 ELF loader for IDA Pro 7.0/7.1
- [**23**Star][6y] [vtsingaras/qcom-mbn-ida-loader](https://github.com/vtsingaras/qcom-mbn-ida-loader) IDA loader plugin for Qualcomm Bootloader Stages
- [**20**Star][3y] [C++] [patois/ndsldr](https://github.com/patois/ndsldr) Nintendo DS ROM loader module for IDA Pro
- [**18**Star][8y] [Py] [rpw/flsloader](https://github.com/rpw/flsloader) IDA Pro loader module for Infineon/Intel-based iPhone baseband firmwares
- [**17**Star][8m] [C++] [gocha/ida-snes-ldr](https://github.com/gocha/ida-snes-ldr) SNES ROM Cartridge File Loader for IDA (Interactive Disassembler) 6.x
- [**16**Star][10m] [Py] [bnbdr/ida-yara-processor](https://github.com/bnbdr/ida-yara-processor) IDA Processor for Compiled YARA Rules
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**16**Star][8m] [C++] [gocha/ida-65816-module](https://github.com/gocha/ida-65816-module) SNES 65816 processor plugin for IDA (Interactive Disassembler) 6.x
- [**16**Star][12m] [Py] [lcq2/riscv-ida](https://github.com/lcq2/riscv-ida) RISC-V ISA processor module for IDAPro 7.x
- [**16**Star][1y] [Py] [ptresearch/nios2](https://github.com/ptresearch/nios2) IDA Pro processor module for Altera Nios II Classic/Gen2 microprocessor architecture
- [**13**Star][2y] [Py] [patois/necromancer](https://github.com/patois/necromancer) IDA Pro V850 Processor Module Extension
- [**13**Star][1y] [Py] [rolfrolles/hiddenbeeloader](https://github.com/rolfrolles/hiddenbeeloader) IDA loader module for Hidden Bee's custom executable file format
- [**10**Star][4y] [C++] [areidz/nds_loader](https://github.com/areidz/nds_loader) Nintendo DS loader module for IDA Pro 6.1
- [**10**Star][6y] [Py] [cycad/mbn_loader](https://github.com/cycad/mbn_loader) IDA Pro Loader Plugin for Samsung Galaxy S4 ROMs
- [**7**Star][1y] [C++] [fail0verflow/rl78-ida-proc](https://github.com/fail0verflow/rl78-ida-proc) Renesas RL78 processor module for IDA
- [**5**Star][8m] [C++] [gocha/ida-spc700-module](https://github.com/gocha/ida-spc700-module) SNES SPC700 processor plugin for IDA (Interactive Disassembler)
- [**3**Star][8m] [C++] [gocha/ida-snes_spc-ldr](https://github.com/gocha/ida-snes_spc-ldr) SNES-SPC700 Sound File Loader for IDA (Interactive Disassembler)
- [**2**Star][2m] [C] [cisco-talos/ida_tilegx](https://github.com/cisco-talos/ida_tilegx) None


### <a id="f5e51763bb09d8fd47ee575a98bedca1"></a>PDB


- [**87**Star][3m] [C++] [mixaill/fakepdb](https://github.com/mixaill/fakepdb) Tool for PDB generation from IDA Pro database
- [**38**Star][1y] [Py] [ax330d/ida_pdb_loader](https://github.com/ax330d/ida_pdb_loader) IDA PDB Loader
- [**14**Star][1y] [CMake] [gdataadvancedanalytics/bindifflib](https://github.com/gdataadvancedanalytics/bindifflib) Automated library compilation and PDB annotation with CMake and IDA Pro
- [**2**Star][5m] [Py] [clarkb7/annotate_lineinfo](https://github.com/clarkb7/annotate_lineinfo) Annotate IDA with source and line number information from a PDB


### <a id="7d0681efba2cf3adaba2780330cd923a"></a>Flash&&SWF


- [**33**Star][1y] [Py] [kasperskylab/actionscript3](https://github.com/kasperskylab/actionscript3) Tools for static and dynamic analysis of ActionScript3 SWF files.
- [**27**Star][4y] [C++] [nihilus/ida-pro-swf](https://github.com/nihilus/ida-pro-swf) None


### <a id="841d605300beba45c3be131988514a03"></a>MalwareFamily


- [**9**Star][2y] [Py] [d00rt/easy_way_nymaim](https://github.com/d00rt/easy_way_nymaim) An IDA Pro script for creating a clearer idb for nymaim malware
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**4**Star][2y] [Py] [immortalp0ny/fyvmdisassembler](https://github.com/immortalp0ny/fyvmdisassembler) IDAPython scripts for devirtualization/disassembly FinSpy VM
- [**4**Star][7m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |


### <a id="ad44205b2d943cfa2fa805b2643f4595"></a>CTF


- [**130**Star][2y] [Py] [pwning/defcon25-public](https://github.com/pwning/defcon25-public) Publicly released tools/plugins from PPP for DEFCON 25 CTF Finals




***


## <a id="ad68872e14f70db53e8d9519213ec039"></a>IDAPython


### <a id="2299bc16945c25652e5ad4d48eae8eca"></a>NoCategory


- [**707**Star][7d] [Py] [idapython/src](https://github.com/idapython/src) IDAPython project for Hex-Ray's IDA Pro
- [**365**Star][1m] [Py] [tmr232/sark](https://github.com/tmr232/sark) IDAPython Made Easy
- [**249**Star][2y] [Py] [intezer/docker-ida](https://github.com/intezer/docker-ida) Run IDA Pro disassembler in Docker containers for automating, scaling and distributing the use of IDAPython scripts.
- [**79**Star][4y] [idapython/bin](https://github.com/idapython/bin) IDAPython binaries
- [**65**Star][2y] [Py] [alexander-hanel/idapython6to7](https://github.com/alexander-hanel/idapython6to7) None
- [**43**Star][1y] [Py] [nirizr/pytest-idapro](https://github.com/nirizr/pytest-idapro) A pytest module for The Interactive Disassembler and IDAPython; Record and Replay IDAPython API, execute inside IDA or use mockups of IDAPython API.
- [**28**Star][2y] [Py] [kerrigan29a/idapython_virtualenv](https://github.com/kerrigan29a/idapython_virtualenv) Enable Virtualenv or Conda in IDAPython
- [**23**Star][3y] [Py] [devttys0/idascript](https://github.com/devttys0/idascript) None


### <a id="c42137cf98d6042372b1fd43c3635135"></a>cheatsheets


- [**232**Star][2m] [Py] [inforion/idapython-cheatsheet](https://github.com/inforion/idapython-cheatsheet) Scripts and cheatsheets for IDAPython




***


## <a id="846eebe73bef533041d74fc711cafb43"></a>InstructRef&&Doc


- [**494**Star][12m] [PLpgSQL] [nologic/idaref](https://github.com/nologic/idaref) IDA Pro Instruction Reference Plugin
- [**441**Star][3m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**242**Star][2y] [Py] [gdelugre/ida-arm-system-highlight](https://github.com/gdelugre/ida-arm-system-highlight) IDA script for highlighting and decoding ARM system instructions
- [**104**Star][25d] [Py] [neatmonster/amie](https://github.com/neatmonster/amie) A Minimalist Instruction Extender for the ARM architecture and IDA Pro
- [**45**Star][8y] [Py] [zynamics/msdn-plugin-ida](https://github.com/zynamics/msdn-plugin-ida) Imports MSDN documentation into IDA Pro
- [**25**Star][3y] [AutoIt] [yaseralnajjar/ida-msdn-helper](https://github.com/yaseralnajjar/IDA-MSDN-helper) IDA Pro MSDN Helper


***


## <a id="c08ebe5b7eec9fc96f8eff36d1d5cc7d"></a>ScriptWritting


### <a id="45fd7cfce682c7c25b4f3fbc4c461ba2"></a>NoCategory


- [**383**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro.
    - Also In Section: [Tools/Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**271**Star][7d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) None
    - Also In Section: [Tools/Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**135**Star][8d] [Py] [arizvisa/ida-minsc](https://github.com/arizvisa/ida-minsc) IDA-minsc is a plugin for IDA Pro that assists a user with scripting the IDAPython plugin that is bundled with the disassembler. This plugin groups the different aspects of the IDAPython API into a simpler format which allows a reverse engineer to script aspects of their work with very little investment. Smash that "Star" button if you like this.
- [**97**Star][23d] [Py] [patois/idapyhelper](https://github.com/patois/idapyhelper) IDAPyHelper is a script for the Interactive Disassembler that helps writing IDAPython scripts and plugins.
- [**74**Star][3m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**42**Star][5m] [C++] [0xeb/ida-climacros](https://github.com/0xeb/ida-climacros) Create and use macros in IDA's CLIs
- [**32**Star][2y] [CMake] [zyantific/ida-cmake](https://github.com/zyantific/ida-cmake) IDA plugin CMake build-script
- [**22**Star][1y] [Py] [nirizr/idasix](https://github.com/nirizr/idasix) IDAPython compatibility library. idasix aims to create a smooth ida development process and allow a single codebase to function with multiple IDA/IDAPython versions
- [**4**Star][6m] [inndy/idapython-cheatsheet](https://github.com/inndy/idapython-cheatsheet) scripting IDA like a Pro


### <a id="1a56a5b726aaa55ec5b7a5087d6c8968"></a>Qt


- [**25**Star][11m] [techbliss/ida_pro_ultimate_qt_build_guide](https://github.com/techbliss/ida_pro_ultimate_qt_build_guide) Ida Pro Ultimate Qt Build Guide
- [**13**Star][2m] [Py] [tmr232/cute](https://github.com/tmr232/cute) Cross-Qt compatibility module for IDAPython.
- [**9**Star][3y] [Py] [techbliss/ida_pro_screen_recorder](https://github.com/techbliss/ida_pro_screen_recorder) PyQt plugin for Ida Pro for Screen recording.


### <a id="1721c09501e4defed9eaa78b8d708361"></a>Console&&GUI


- [**260**Star][17d] [Py] [eset/ipyida](https://github.com/eset/ipyida) IPython console integration for IDA Pro
- [**231**Star][2y] [Jupyter Notebook] [james91b/ida_ipython](https://github.com/james91b/ida_ipython) An IDA Pro Plugin for embedding an IPython Kernel
- [**175**Star][3m] [Py] [techbliss/python_editor](https://github.com/techbliss/python_editor) Better CodeEditor for Ida Pro.


### <a id="227fbff77e3a13569ef7b007344d5d2e"></a>Template


- [**5**Star][2y] [C++] [patois/ida_vs2017](https://github.com/patois/ida_vs2017) IDA 7.x VisualStudio 2017 Sample Project for IDA and HexRays plugins (works with Community Edition)
- [**4**Star][5y] [JS] [nihilus/ida-pro-plugin-wizard-for-vs2013](https://github.com/nihilus/ida-pro-plugin-wizard-for-vs2013) None


### <a id="8b19bb8cf9a5bc9e6ab045f3b4fabf6a"></a>OtherLang


- [**22**Star][3y] [Java] [cblichmann/idajava](https://github.com/cblichmann/idajava) Java integration for Hex-Rays IDA Pro
- [**8**Star][3y] [C++] [nlitsme/idaperl](https://github.com/nlitsme/idaperl) perl scripting support for IDApro




***


## <a id="dc35a2b02780cdaa8effcae2b6ce623e"></a>Ancient


- [**163**Star][4y] [Py] [osirislab/fentanyl](https://github.com/osirislab/Fentanyl) Fentanyl is an IDAPython script that makes patching significantly easier
- [**127**Star][6y] [C++] [crowdstrike/crowddetox](https://github.com/crowdstrike/crowddetox) None
- [**94**Star][5y] [Py] [nihilus/ida-idc-scripts](https://github.com/nihilus/ida-idc-scripts) Varoius IDC-scripts I've collected during the years.
- [**83**Star][6y] [Py] [einstein-/hexrays-python](https://github.com/einstein-/hexrays-python) Python bindings for the Hexrays Decompiler
- [**76**Star][5y] [PHP] [v0s/plus22](https://github.com/v0s/plus22) Tool to analyze 64-bit binaries with 32-bit Hex-Rays Decompiler
- [**63**Star][5y] [C] [nihilus/idastealth](https://github.com/nihilus/idastealth) None
- [**40**Star][6y] [C++] [wirepair/idapinlogger](https://github.com/wirepair/idapinlogger) Logs instruction hits to a file which can be fed into IDA Pro to highlight which instructions were called.
- [**39**Star][10y] [izsh/ida-python-scripts](https://github.com/izsh/ida-python-scripts) IDA Python Scripts
- [**39**Star][8y] [Py] [zynamics/bincrowd-plugin-ida](https://github.com/zynamics/bincrowd-plugin-ida) BinCrowd Plugin for IDA Pro
- [**35**Star][8y] [Py] [zynamics/ida2sql-plugin-ida](https://github.com/zynamics/ida2sql-plugin-ida) None
- [**27**Star][4y] [C++] [luorui110120/idaplugins](https://github.com/luorui110120/idaplugins) ida插件
- [**21**Star][10y] [C++] [sporst/ida-pro-plugins](https://github.com/sporst/ida-pro-plugins) Collection of IDA Pro plugins I wrote over the years
- [**18**Star][10y] [Py] [binrapt/ida](https://github.com/binrapt/ida) Python script which extracts procedures from IDA Win32 LST files and converts them to correctly dynamically linked compilable Visual C++ inline assembly.
- [**15**Star][7y] [Py] [nihilus/optimice](https://github.com/nihilus/optimice) None
- [**10**Star][10y] [jeads-sec/etherannotate_ida](https://github.com/jeads-sec/etherannotate_ida) EtherAnnotate IDA Pro Plugin - Parse EtherAnnotate trace files and markup IDA disassemblies with runtime values
- [**6**Star][10y] [C] [jeads-sec/etherannotate_xen](https://github.com/jeads-sec/etherannotate_xen) EtherAnnotate Xen Ether Modification - Adds a feature to Ether that pulls register values and potential string values at each instruction during an instruction trace.


***


## <a id="e3e7030efc3b4de3b5b8750b7d93e6dd"></a>Debug&&DynamicData


### <a id="2944dda5289f494e5e636089db0d6a6a"></a>NoCategory


- [**390**Star][11m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [Tools/Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**184**Star][5y] [C++] [nihilus/scyllahide](https://github.com/nihilus/scyllahide) None
- [**105**Star][1m] [Py] [danielplohmann/apiscout](https://github.com/danielplohmann/apiscout) This project aims at simplifying Windows API import recovery on arbitrary memory dumps
- [**81**Star][4y] [C++] [wjp/idados](https://github.com/wjp/idados) Eric Fry's IDA/DOSBox debugger plugin
    - Also In Section: [Tools/SpecificTarget/NoCategory](#5578c56ca09a5804433524047840980e) |
- [**56**Star][7y] [Py] [cr4sh/ida-vmware-gdb](https://github.com/cr4sh/ida-vmware-gdb) Helper script for Windows kernel debugging with IDA Pro on VMware + GDB stub
- [**42**Star][5y] [Py] [nihilus/idasimulator](https://github.com/nihilus/idasimulator) IDASimulator is a plugin that extends IDA's conditional breakpoint support, making it easy to augment / replace complex executable code inside a debugged process with Python code. Specifically, IDASimulator makes use of conditional breakpoints in the IDA debugger to hijack the execution flow of a process and invoke Python handler functions whene…
- [**38**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [Tools/Android](#66052f824f5054aa0f70785a2389a478) |
- [**22**Star][5y] [Py] [techbliss/scylladumper](https://github.com/techbliss/scylladumper) Ida Plugin to Use the Awsome Scylla plugin
- [**14**Star][5y] [Py] [techbliss/free_the_debuggers](https://github.com/techbliss/free_the_debuggers) Free_the_Debuggers
- [**0**Star][2y] [Py] [benh11235/ida-windbglue](https://github.com/benh11235/ida-windbglue) Humble suite of scripts to assist with remote debugging using IDA pro client and winDBG server.


### <a id="0fbd352f703b507853c610a664f024d1"></a>DBIData


- [**929**Star][11m] [Py] [gaasedelen/lighthouse](https://github.com/gaasedelen/lighthouse) Code Coverage Explorer for IDA Pro & Binary Ninja
    - [coverage-frida](https://github.com/gaasedelen/lighthouse/blob/master/coverage/frida/README.md) 使用Frida收集信息
    - [coverage-pin](https://github.com/gaasedelen/lighthouse/blob/master/coverage/pin/README.md) 使用Pin收集覆盖信息
    - [插件](https://github.com/gaasedelen/lighthouse/blob/master/plugin/lighthouse_plugin.py) 支持IDA和BinNinja
- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/IntelPin](#dd0332da5a1482df414658250e6357f8) |[Tools/Vul/NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**129**Star][3y] [Py] [friedappleteam/frapl](https://github.com/friedappleteam/frapl) FRAPL Framework
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/Frida](#a1cf7f7f849b4ca2101bd31449c2a0fd) |
    - [IDA插件](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FridaLink) 
    - [Frida脚本](https://github.com/FriedAppleTeam/FRAPL/tree/master/Framework/FRAPL) 
- [**121**Star][5y] [C++] [zachriggle/ida-splode](https://github.com/zachriggle/ida-splode) Augmenting Static Reverse Engineering with Dynamic Analysis and Instrumentation
    - [IDA插件](https://github.com/zachriggle/ida-splode/tree/master/py) 
    - [PinTool](https://github.com/zachriggle/ida-splode/tree/master/src) 
- [**117**Star][2y] [C++] [0xphoenix/mazewalker](https://github.com/0xphoenix/mazewalker) Toolkit for enriching and speeding up static malware analysis
    - [mazeui](https://github.com/0xphoenix/mazewalker/blob/master/MazeUI/mazeui.py) 在IDA中显示界面
    - [PyScripts](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/PyScripts) Python脚本，处理收集到的数据
    - [PinClient](https://github.com/0xPhoeniX/MazeWalker/tree/master/MazeTracer/src) 
- [**88**Star][8y] [C] [neuroo/runtime-tracer](https://github.com/neuroo/runtime-tracer) Dynamic tracing for binary applications (using PIN), IDA plugin to visualize and interact with the traces
    - [PinTool](https://github.com/neuroo/runtime-tracer/tree/master/tracer) 
    - [IDA插件](https://github.com/neuroo/runtime-tracer/tree/master/ida-pin) 
- [**79**Star][3y] [Py] [davidkorczynski/repeconstruct](https://github.com/davidkorczynski/repeconstruct) None
- [**51**Star][10m] [Py] [cisco-talos/dyndataresolver](https://github.com/cisco-talos/dyndataresolver) None
    - [DDR](https://github.com/cisco-talos/dyndataresolver/blob/master/VS_project/ddr/ddr.sln) 基于DyRIO的Client
    - [IDA插件](https://github.com/cisco-talos/dyndataresolver/tree/master/IDAplugin) 
- [**20**Star][8m] [C++] [secrary/findloop](https://github.com/secrary/findloop) findLoop - find possible encryption/decryption or compression/decompression code
- [**15**Star][12m] [C++] [agustingianni/instrumentation](https://github.com/agustingianni/instrumentation) Assorted pintools
    - [CodeCoverage](https://github.com/agustingianni/instrumentation/tree/master/CodeCoverage) 
    - [Pinnacle](https://github.com/agustingianni/instrumentation/tree/master/Pinnacle) 
    - [Recoverer](https://github.com/agustingianni/instrumentation/tree/master/Recoverer) 
    - [Resolver](https://github.com/agustingianni/instrumentation/tree/master/Resolver) 


### <a id="b31acf6c84a9506066d497af4e702bf5"></a>DebuggerData


- [**595**Star][2m] [Py] [0xgalz/virtuailor](https://github.com/0xgalz/virtuailor) IDAPython tool for creating automatic C++ virtual tables in IDA Pro
    - Also In Section: [Tools/Structure&&Class/C++Class&&VirtualTable](#4900b1626f10791748b20630af6d6123) |
        <details>
        <summary>View Details</summary>


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


- [**383**Star][4m] [Py] [ynvb/die](https://github.com/ynvb/die) Dynamic IDA Enrichment
- [**378**Star][4y] [Py] [deresz/funcap](https://github.com/deresz/funcap) IDA Pro script to add some useful runtime info to static analysis
- [**103**Star][3y] [Py] [c0demap/codemap](https://github.com/c0demap/codemap) Codemap
    - [IDA插件](https://github.com/c0demap/codemap/blob/master/idapythonrc.py) 
    - [Web服务器](https://github.com/c0demap/codemap/tree/master/codemap/server) 




***


## <a id="d2166f4dac4eab7fadfe0fd06467fbc9"></a>Decompiler&&AST


- [**1661**Star][6m] [C++] [yegord/snowman](https://github.com/yegord/snowman) Snowman decompiler
    - [IDA插件](https://github.com/yegord/snowman/tree/master/src/ida-plugin) 
    - [snowman](https://github.com/yegord/snowman/tree/master/src/snowman) QT界面
    - [nocode](https://github.com/yegord/snowman/tree/master/src/nocode) 命令行工具
    - [nc](https://github.com/yegord/snowman/tree/master/src/nc) 核心代码，可作为库使用
- [**1317**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**465**Star][4y] [Py] [einstein-/decompiler](https://github.com/EiNSTeiN-/decompiler) A decompiler with multiple backend support, written in Python. Works with IDA and Capstone.
- [**400**Star][2m] [C++] [avast/retdec-idaplugin](https://github.com/avast/retdec-idaplugin) RetDec plugin for IDA
- [**291**Star][5y] [C++] [smartdec/smartdec](https://github.com/smartdec/smartdec) SmartDec decompiler
    - [IDA插件](https://github.com/smartdec/smartdec/tree/master/src/ida-plugin) 
    - [nocode](https://github.com/smartdec/smartdec/tree/master/src/nocode) 命令行反编译器
    - [smartdec](https://github.com/smartdec/smartdec/tree/master/src/smartdec) 带GUI界面的反编译器
    - [nc](https://github.com/smartdec/smartdec/tree/master/src/nc) 反编译器的核心代码
- [**286**Star][5y] [Py] [aaronportnoy/toolbag](https://github.com/aaronportnoy/toolbag) The IDA Toolbag is a plugin providing supplemental functionality to Hex-Rays IDA Pro disassembler.
- [**225**Star][6m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**167**Star][1y] [Py] [tintinweb/ida-batch_decompile](https://github.com/tintinweb/ida-batch_decompile) *Decompile All the Things* - IDA Batch Decompile plugin and script for Hex-Ray's IDA Pro that adds the ability to batch decompile multiple files and their imports with additional annotations (xref, stack var size) to the pseudocode .c file
- [**149**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**103**Star][7m] [Py] [sibears/hrast](https://github.com/sibears/hrast) PoC of modifying HexRays AST
- [**89**Star][5m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**41**Star][27d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) MrsPicky - An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [Tools/Vul/NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
- [**23**Star][1y] [C++] [dougallj/dj_ida_plugins](https://github.com/dougallj/dj_ida_plugins) Plugins for IDA Pro and Hex-Rays


***


## <a id="7199e8787c0de5b428f50263f965fda7"></a>DeObfuscate


- [**1351**Star][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**539**Star][2y] [Py] [anatolikalysch/vmattack](https://github.com/anatolikalysch/vmattack) VMAttack PlugIn for IDA Pro
    - Also In Section: [Tools/SpecificTarget/NoCategory](#5578c56ca09a5804433524047840980e) |
- [**290**Star][3m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [Tools/Microcode](#7a2977533ccdac70ee6e58a7853b756b) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [Tools/Emulator](#b38dab81610be087bd5bc7785269b8cc) |
- [**47**Star][2y] [Py] [riscure/drop-ida-plugin](https://github.com/riscure/drop-ida-plugin) Experimental opaque predicate detection for IDA Pro
- [**22**Star][3m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [Tools/TaintAnalysis&&SymbolicExecution](#34ac84853604a7741c61670f2a075d20) |
- [**8**Star][3y] [Py] [thngkaiyuan/mynaim](https://github.com/thngkaiyuan/mynaim) IDAPython Deobfuscation Scripts for Nymaim Samples
    - Also In Section: [Tools/SpecificTarget/MalwareFamily](#841d605300beba45c3be131988514a03) |


***


## <a id="fcf75a0881617d1f684bc8b359c684d7"></a>Nav&&QuickAccess&&Graph&&Image


### <a id="c5b120e1779b928d860ad64ff8d23264"></a>NoCategory


- [**1317**Star][1y] [C++] [rehints/hexrayscodexplorer](https://github.com/rehints/hexrayscodexplorer) Hex-Rays Decompiler plugin for better code navigation
    - Also In Section: [Tools/Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
        <details>
        <summary>View Details</summary>


        - 自动类型重建
        - 虚表识别/导航(反编译窗口)
        - C-tree可视化与导出
        - 对象浏览
        </details>


- [**441**Star][3m] [C++] [alexhude/friend](https://github.com/alexhude/friend) Flexible Register/Instruction Extender aNd Documentation
    - Also In Section: [Tools/InstructRef&&Doc](#846eebe73bef533041d74fc711cafb43) |
- [**362**Star][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[Tools/Vul/NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**327**Star][2m] [Py] [pfalcon/scratchabit](https://github.com/pfalcon/scratchabit) Easily retargetable and hackable interactive disassembler with IDAPython-compatible plugin API
- [**225**Star][6m] [Py] [patois/dsync](https://github.com/patois/dsync) IDAPython plugin that synchronizes disassembler and decompiler views
    - Also In Section: [Tools/Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**183**Star][24d] [Py] [danigargu/dereferencing](https://github.com/danigargu/dereferencing) IDA Pro plugin that implements more user-friendly register and stack views
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |
- [**98**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[Tools/Function/Nav&&Search](#e4616c414c24b58626f834e1be079ebc) |
- [**80**Star][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [Tools/Function/Nav&&Search](#e4616c414c24b58626f834e1be079ebc) |
- [**74**Star][3m] [C++] [0xeb/ida-qscripts](https://github.com/0xeb/ida-qscripts) An IDA plugin to increase productivity when developing scripts for IDA
    - Also In Section: [Tools/ScriptWritting/NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**48**Star][2m] [C++] [jinmo/ifred](https://github.com/jinmo/ifred) IDA command palette & more (Ctrl+Shift+P, Ctrl+P)
- [**40**Star][4m] [Py] [tmr232/brutal-ida](https://github.com/tmr232/brutal-ida) Block Redo & Undo To Achieve Legacy IDA
- [**23**Star][6y] [C++] [cr4sh/ida-ubigraph](https://github.com/cr4sh/ida-ubigraph) IDA Pro plug-in and tools for displaying 3D graphs of procedures using UbiGraph
- [**17**Star][2y] [Py] [tmr232/graphgrabber](https://github.com/tmr232/graphgrabber) None
- [**5**Star][2y] [Py] [handsomematt/ida_func_ptr](https://github.com/handsomematt/ida_func_ptr) Easily create and copy function pointers to functions in IDA.


### <a id="03fac5b3abdbd56974894a261ce4e25f"></a>GUIEnhencement


- [**200**Star][1m] [Py] [patois/idacyber](https://github.com/patois/idacyber) Data Visualization Plugin for IDA Pro
- [**149**Star][1y] [Py] [ax330d/hrdev](https://github.com/ax330d/hrdev) Hex-Rays Decompiler Enhanced View
    - Also In Section: [Tools/Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**104**Star][2y] [Py] [danigargu/idatropy](https://github.com/danigargu/idatropy) IDAtropy is a plugin for Hex-Ray's IDA Pro designed to generate charts of entropy and histograms using the power of idapython and matplotlib.
- [**89**Star][5m] [Py] [patois/hrdevhelper](https://github.com/patois/hrdevhelper) HexRays decompiler plugin that visualizes the ctree of decompiled functions.
    - Also In Section: [Tools/Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**47**Star][1m] [Py] [patois/xray](https://github.com/patois/xray) Hexrays decompiler plugin that colorizes and filters the decompiler's output based on regular expressions
- [**20**Star][3m] [C++] [revspbird/hightlight](https://github.com/revspbird/hightlight) a plugin for ida of version 7.2 to help know F5 window codes better
- [**5**Star][3y] [Py] [oct0xor/ida_pro_graph_styling](https://github.com/oct0xor/ida_pro_graph_styling) Advanced Ida Pro Instruction Highlighting
- [**5**Star][2y] [C] [teppay/ida](https://github.com/teppay/ida) my files related to IDA
- [**4**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [Tools/Function/NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |


### <a id="3b1dba00630ce81cba525eea8fcdae08"></a>Graph


- [**2562**Star][4m] [Java] [google/binnavi](https://github.com/google/binnavi) BinNavi is a binary analysis IDE that allows to inspect, navigate, edit and annotate control flow graphs and call graphs of disassembled code.
- [**231**Star][2y] [C++] [fireeye/simplifygraph](https://github.com/fireeye/simplifygraph) IDA Pro plugin to assist with complex graphs
- [**39**Star][8m] [Py] [rr-/ida-images](https://github.com/rr-/ida-images) Image preview plugin for IDA disassembler.


### <a id="8f9468e9ab26128567f4be87ead108d7"></a>Search


- [**149**Star][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [Tools/Function/Nav&&Search](#e4616c414c24b58626f834e1be079ebc) |
- [**64**Star][3y] [Py] [xorpd/idsearch](https://github.com/xorpd/idsearch) A search tool for IDA
- [**23**Star][4m] [Py] [alexander-hanel/hansel](https://github.com/alexander-hanel/hansel) Hansel - a simple but flexible search for IDA




***


## <a id="66052f824f5054aa0f70785a2389a478"></a>Android


- [**223**Star][2y] [Py] [strazzere/android-scripts](https://github.com/strazzere/android-scripts) Collection of Android reverse engineering scripts
- [**158**Star][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Tools/SpecificTarget/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**115**Star][4y] [Py] [cvvt/dumpdex](https://github.com/cvvt/dumpdex) IDA python script to dynamically dump DEX in memory
- [**79**Star][2y] [Py] [zhkl0228/androidattacher](https://github.com/zhkl0228/androidattacher) IDA debugging plugin for android armv7 so
- [**39**Star][5y] [Py] [techbliss/adb_helper_qt_super_version](https://github.com/techbliss/adb_helper_qt_super_version) All You Need For Ida Pro And Android Debugging
- [**38**Star][2y] [Py] [thecjw/ida_android_script](https://github.com/thecjw/ida_android_script) some idapython scripts for android debugging.
    - Also In Section: [Tools/Debug&&DynamicData/NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**16**Star][7y] [C++] [strazzere/dalvik-header-plugin](https://github.com/strazzere/dalvik-header-plugin) Dalvik Header Plugin for IDA Pro


***


## <a id="2adc0044b2703fb010b3bf73b1f1ea4a"></a>Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O


### <a id="8530752bacfb388f3726555dc121cb1a"></a>NoCategory


- [**173**Star][2y] [Py] [duo-labs/idapython](https://github.com/duo-labs/idapython) A collection of IDAPython modules made with
    - Also In Section: [Tools/Firmware&&EmbedDevice](#a8f5db3ab4bc7bc3d6ca772b3b9b0b1e) |
    - [cortex_m_firmware](https://github.com/duo-labs/idapython/blob/master/cortex_m_firmware.py)  整理包含ARM Cortex M微控制器固件的IDA Pro数据库
    - [amnesia](https://github.com/duo-labs/idapython/blob/master/amnesia.py) 使用字节级启发式在IDA Pro数据库中的未定义字节中查找ARM Thumb指令
    - [REobjc](https://github.com/duo-labs/idapython/blob/master/reobjc.py) 在Objective-C的调用函数和被调用函数之间进行适当的交叉引用
- [**167**Star][8y] [Py] [zynamics/objc-helper-plugin-ida](https://github.com/zynamics/objc-helper-plugin-ida) Simplifies working with Objective-C binaries in IDA Pro
- [**19**Star][2y] [aozhimin/ios-monitor-resources](https://github.com/aozhimin/ios-monitor-resources) 对各厂商的 iOS SDK 性能监控方案的整理和收集后的资源
- [**17**Star][9y] [C++] [alexander-pick/patchdiff2_ida6](https://github.com/alexander-pick/patchdiff2_ida6) patched up patchdiff2 to compile and work with IDA 6 on OSX
- [**14**Star][8y] [Standard ML] [letsunlockiphone/iphone-baseband-ida-pro-signature-files](https://github.com/letsunlockiphone/iphone-baseband-ida-pro-signature-files) IDA PRO signature files that can be used in reversing the iPhone baseband. On an iPhone 4 firmware can pickup upto 800 functions when all the sigs applied.
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/NoCategory](#cf04b98ea9da0056c055e2050da980c1) |


### <a id="82d0fa2d6934ce29794a651513934384"></a>kernelCache


- [**168**Star][12m] [Py] [bazad/ida_kernelcache](https://github.com/bazad/ida_kernelcache) An IDA Toolkit for analyzing iOS kernelcaches.
    - Also In Section: [Tools/Structure&&Class/NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**137**Star][8y] [stefanesser/ida-ios-toolkit](https://github.com/stefanesser/ida-ios-toolkit) Collection of idapython scripts for dealing with the iOS kernelcache
- [**50**Star][1y] [Py] [synacktiv-contrib/kernelcache-laundering](https://github.com/Synacktiv-contrib/kernelcache-laundering) load iOS12 kernelcaches and PAC code in IDA


### <a id="d249a8d09a3f25d75bb7ba8b32bd9ec5"></a>Mach-O


- [**47**Star][7m] [C] [gdbinit/extractmacho](https://github.com/gdbinit/extractmacho) IDA plugin to extract Mach-O binaries located in the disassembly or data
- [**18**Star][3y] [C] [cocoahuke/iosdumpkernelfix](https://github.com/cocoahuke/iosdumpkernelfix) This tool will help to fix the Mach-O header of iOS kernel which dump from the memory. So that IDA or function symbol-related tools can loaded function symbols of ios kernel correctly
- [**17**Star][8y] [C] [gdbinit/machoplugin](https://github.com/gdbinit/machoplugin) IDA plugin to Display Mach-O headers


### <a id="1c698e298f6112a86c12881fbd8173c7"></a>Swift


- [**17**Star][3y] [Py] [tylerha97/swiftdemang](https://github.com/0xtyh/swiftdemang) IDA Pro IDAPython Script to Demangle Swift
- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [Tools/Function/demangle](#cadae88b91a57345d266c68383eb05c5) |




***


## <a id="e5e403123c70ddae7bd904d3a3005dbb"></a>ELF


- [**518**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [Tools/Patch](#7d557bc3d677d206ef6c5a35ca8b3a14) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**202**Star][5y] [C] [snare/ida-efiutils](https://github.com/snare/ida-efiutils) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**158**Star][1m] [Py] [nforest/droidimg](https://github.com/nforest/droidimg) Android/Linux vmlinux loader
    - Also In Section: [Tools/Android](#66052f824f5054aa0f70785a2389a478) |[Tools/SpecificTarget/Loader&Processor](#cb59d84840e41330a7b5e275c0b81725) |
- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/Radare2](#21ed198ae5a974877d7a635a4b039ae3) |[Tools/Function/NoCategory](#347a2158bdd92b00cd3d4ba9a0be00ae) |
- [**90**Star][2y] [C++] [gdbinit/efiswissknife](https://github.com/gdbinit/efiswissknife) An IDA plugin to improve (U)EFI reversing
- [**83**Star][2m] [Py] [yeggor/uefi_retool](https://github.com/yeggor/uefi_retool) 
- [**44**Star][2y] [C] [aerosoul94/dynlib](https://github.com/aerosoul94/dynlib) IDA Pro plugin to aid PS4 user mode ELF reverse engineering.
    - Also In Section: [Tools/SpecificTarget/PS3&&PS4](#315b1b8b41c67ae91b841fce1d4190b5) |
- [**44**Star][4y] [Py] [danse-macabre/ida-efitools](https://github.com/danse-macabre/ida-efitools) Some scripts for IDA Pro to assist with reverse engineering EFI binaries
- [**43**Star][4y] [Py] [strazzere/idant-wanna](https://github.com/strazzere/idant-wanna) ELF header abuse


***


## <a id="7a2977533ccdac70ee6e58a7853b756b"></a>Microcode


- [**290**Star][3m] [C++] [rolfrolles/hexraysdeob](https://github.com/rolfrolles/hexraysdeob) Hex-Rays microcode API plugin for breaking an obfuscating compiler
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**186**Star][4m] [C++] [chrisps/hexext](https://github.com/chrisps/Hexext) Hexext is a plugin to improve the output of the hexrays decompiler through microcode manipulation.
- [**60**Star][4m] [Py] [patois/genmc](https://github.com/patois/genmc) Display Hex-Rays Microcode
- [**43**Star][1m] [Py] [idapython/pyhexraysdeob](https://github.com/idapython/pyhexraysdeob) A port of Rolf Rolles'
- [**19**Star][8m] [Py] [neatmonster/mcexplorer](https://github.com/neatmonster/mcexplorer) Python portage of the Microcode Explorer plugin


***


## <a id="b38dab81610be087bd5bc7785269b8cc"></a>Emulator


- [**482**Star][12m] [Py] [alexhude/uemu](https://github.com/alexhude/uemu) Tiny cute emulator plugin for IDA based on unicorn.
- [**390**Star][11m] [C++] [cseagle/sk3wldbg](https://github.com/cseagle/sk3wldbg) Debugger plugin for IDA Pro backed by the Unicorn Engine
    - Also In Section: [Tools/Debug&&DynamicData/NoCategory](#2944dda5289f494e5e636089db0d6a6a) |
- [**383**Star][3y] [Py] [36hours/idaemu](https://github.com/36hours/idaemu) idaemu is an IDA Pro Plugin - use for emulating code in IDA Pro.
    - Also In Section: [Tools/ScriptWritting/NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**271**Star][7d] [Py] [fireeye/flare-emu](https://github.com/fireeye/flare-emu) None
    - Also In Section: [Tools/ScriptWritting/NoCategory](#45fd7cfce682c7c25b4f3fbc4c461ba2) |
- [**202**Star][2y] [Py] [tkmru/nao](https://github.com/tkmru/nao) Simple No-meaning Assembly Omitter for IDA Pro (CURRENTLY UNDER DEVELOPMENT)
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
- [**124**Star][2y] [Py] [codypierce/pyemu](https://github.com/codypierce/pyemu) x86 Emulator in Python


***


## <a id="83de90385d03ac8ef27360bfcdc1ab48"></a>PartOfOtherTool


- [**1515**Star][13d] [Py] [lifting-bits/mcsema](https://github.com/lifting-bits/mcsema) Framework for lifting x86, amd64, and aarch64 program binaries to LLVM bitcode
    - [IDA7插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida7) 用于反汇编二进制文件并生成控制流程图
    - [IDA插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/ida) 用于反汇编二进制文件并生成控制流程图
    - [Binja插件](https://github.com/lifting-bits/mcsema/tree/master/tools/mcsema_disass/binja) 用于反汇编二进制文件并生成控制流程图
    - [mcsema](https://github.com/lifting-bits/mcsema/tree/master/mcsema) 
- [**416**Star][22d] [C] [mcgill-dmas/kam1n0-community](https://github.com/McGill-DMaS/Kam1n0-Community) The Kam1n0 Assembly Analysis Platform
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/NoCategory](#cf04b98ea9da0056c055e2050da980c1) |
    - [IDA插件](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0-clients/ida-plugin) 
    - [kam1n0](https://github.com/McGill-DMaS/Kam1n0-Community/tree/master2.x/kam1n0) 
- [**27**Star][4y] [Scheme] [yifanlu/cgen](https://github.com/yifanlu/cgen) CGEN with support for generating IDA Pro IDP modules
- [**23**Star][2y] [Py] [tintinweb/unbox](https://github.com/tintinweb/unbox) 


***


## <a id="1ded622dca60b67288a591351de16f8b"></a>Vul


### <a id="385d6777d0747e79cccab0a19fa90e7e"></a>NoCategory


- [**489**Star][6m] [Py] [danigargu/heap-viewer](https://github.com/danigargu/heap-viewer) An IDA Pro plugin to examine the glibc heap, focused on exploit development
- [**376**Star][2y] [Py] [1111joe1111/ida_ea](https://github.com/1111joe1111/ida_ea) A set of exploitation/reversing aids for IDA
- [**362**Star][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**137**Star][6m] [Py] [iphelix/ida-sploiter](https://github.com/iphelix/ida-sploiter) IDA Sploiter is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's capabilities as an exploit development and vulnerability research tool.
- [**133**Star][1y] [Py] [carlosgprado/jarvis](https://github.com/carlosgprado/jarvis) "Just Another ReVersIng Suite" or whatever other bullshit you can think of
    - Also In Section: [Tools/ImportExport&&SyncWithOtherTools/IntelPin](#dd0332da5a1482df414658250e6357f8) |[Tools/Debug&&DynamicData/DBIData](#0fbd352f703b507853c610a664f024d1) |
    - [IDA插件](https://github.com/carlosgprado/jarvis/tree/master/IDAPlugin) 
    - [PinTracer](https://github.com/carlosgprado/jarvis/tree/master/PinTracer) 
- [**41**Star][27d] [Py] [patois/mrspicky](https://github.com/patois/mrspicky) MrsPicky - An IDAPython decompiler script that helps auditing calls to the memcpy() and memmove() functions.
    - Also In Section: [Tools/Decompiler&&AST](#d2166f4dac4eab7fadfe0fd06467fbc9) |
- [**32**Star][6y] [Py] [coldheat/quicksec](https://github.com/coldheat/quicksec) IDAPython script for quick vulnerability analysis


### <a id="cf2efa7e3edb24975b92d2e26ca825d2"></a>ROP


- [**53**Star][3y] [Py] [patois/drgadget](https://github.com/patois/drgadget) dr.rer.oec.gadget IDAPython plugin for the Interactive Disassembler <ABANDONED PROJECT>
- [**19**Star][1y] [Py] [lucasg/idarop](https://github.com/lucasg/idarop) ROP database plugin for IDA




***


## <a id="7d557bc3d677d206ef6c5a35ca8b3a14"></a>Patch


- [**713**Star][12m] [Py] [keystone-engine/keypatch](https://github.com/keystone-engine/keypatch) Multi-architecture assembler for IDA Pro. Powered by Keystone Engine.
- [**518**Star][2y] [C] [lunixbochs/patchkit](https://github.com/lunixbochs/patchkit) binary patching from Python
    - Also In Section: [Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |
    - [IDA插件](https://github.com/lunixbochs/patchkit/tree/master/ida) 
    - [patchkit](https://github.com/lunixbochs/patchkit/tree/master/core) 
- [**87**Star][5y] [Py] [iphelix/ida-patcher](https://github.com/iphelix/ida-patcher) IDA Patcher is a plugin for Hex-Ray's IDA Pro disassembler designed to enhance IDA's ability to patch binary files and memory.
- [**42**Star][3y] [C++] [mrexodia/idapatch](https://github.com/mrexodia/idapatch) IDA plugin to patch IDA Pro in memory.
- [**30**Star][3m] [Py] [scottmudge/debugautopatch](https://github.com/scottmudge/debugautopatch) Patching system improvement plugin for IDA.
- [**16**Star][8y] [C++] [jkoppel/reprogram](https://github.com/jkoppel/reprogram) Patch binaries at load-time
- [**0**Star][7m] [Py] [tkmru/genpatch](https://github.com/tkmru/genpatch) genpatch is IDA plugin that generates a python script for patch


***


## <a id="7dfd8abad50c14cd6bdc8d8b79b6f595"></a>Other


- [**120**Star][2y] [Shell] [feicong/ida_for_mac_green](https://github.com/feicong/ida_for_mac_green) IDA Pro for macOS绿化
- [**28**Star][4m] [angelkitty/ida7.0](https://github.com/angelkitty/ida7.0) 
- [**16**Star][2y] [jas502n/ida7.0-pro](https://github.com/jas502n/ida7.0-pro) some people share IDA7.0！


***


## <a id="90bf5d31a3897400ac07e15545d4be02"></a>Function


### <a id="347a2158bdd92b00cd3d4ba9a0be00ae"></a>NoCategory


- [**125**Star][7m] [Py] [danigargu/syms2elf](https://github.com/danigargu/syms2elf) A plugin for Hex-Ray's IDA Pro and radare2 to export the symbols recognized to the ELF symbol table
    - Also In Section: [Tools/ELF](#e5e403123c70ddae7bd904d3a3005dbb) |[Tools/ImportExport&&SyncWithOtherTools/Radare2](#21ed198ae5a974877d7a635a4b039ae3) |
- [**11**Star][2y] [C++] [fireundubh/ida7-functionstringassociate](https://github.com/fireundubh/ida7-functionstringassociate) FunctionStringAssociate plugin by sirmabus, ported to IDA 7
- [**4**Star][2y] [Py] [andreafioraldi/idaretaddr](https://github.com/andreafioraldi/idaretaddr) Highlight the return address of a function in the Ida Pro debugger
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/GUIEnhencement](#03fac5b3abdbd56974894a261ce4e25f) |
- [**2**Star][4m] [Py] [farzonl/idapropluginlab3](https://github.com/farzonl/idapropluginlab3) An Ida plugin that does static analysis to describe what malware is doing.


### <a id="73813456eeb8212fd45e0ea347bec349"></a>Rename&&Prefix&&Tag


- [**285**Star][1m] [Py] [a1ext/auto_re](https://github.com/a1ext/auto_re) IDA PRO auto-renaming plugin with tagging support
- [**117**Star][5y] [C++] [zyantific/retypedef](https://github.com/zyantific/retypedef) Name substitution plugin for IDA Pro
- [**95**Star][2y] [Py] [gaasedelen/prefix](https://github.com/gaasedelen/prefix) Function Prefixing for IDA Pro
- [**47**Star][3y] [Py] [alessandrogario/ida-function-tagger](https://github.com/alessandrogario/ida-function-tagger) This IDAPython script tags subroutines according to their use of imported functions
- [**21**Star][11m] [Py] [howmp/comfinder](https://github.com/howmp/comfinder) IDA plugin for COM
    - Also In Section: [Tools/SpecificTarget/NoCategory](#5578c56ca09a5804433524047840980e) |
- [**3**Star][4y] [Py] [ayuto/discover_win](https://github.com/ayuto/discover_win) IDA scripts which compare Linux and Windows binaries to automatically rename unnamed Windows functions.
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/NoCategory](#cf04b98ea9da0056c055e2050da980c1) |


### <a id="e4616c414c24b58626f834e1be079ebc"></a>Nav&&Search


- [**178**Star][5m] [Py] [hasherezade/ida_ifl](https://github.com/hasherezade/ida_ifl) IFL - Interactive Functions List (plugin for IDA Pro)
- [**149**Star][2y] [Py] [ga-ryo/idafuzzy](https://github.com/ga-ryo/idafuzzy) Fuzzy search tool for IDA Pro.
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/Search](#8f9468e9ab26128567f4be87ead108d7) |
- [**98**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [Tools/string](#9dcc6c7dd980bec1f92d0cc9a2209a24) |[Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**80**Star][1y] [Py] [ax330d/functions-plus](https://github.com/ax330d/functions-plus) IDA Pro plugin to show functions in a tree view
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**33**Star][3y] [Py] [darx0r/reef](https://github.com/darx0r/reef) IDAPython plugin for finding Xrefs from a function


### <a id="cadae88b91a57345d266c68383eb05c5"></a>demangle


- [**17**Star][4y] [Py] [gsingh93/ida-swift-demangle](https://github.com/gsingh93/ida-swift-demangle) An IDA plugin to demangle Swift function names
    - Also In Section: [Tools/Apple&&macOS&&iXxx&&Objective-C&&SWift&&Mach-O/Swift](#1c698e298f6112a86c12881fbd8173c7) |
- [**14**Star][1y] [Py] [ax330d/exports-plus](https://github.com/ax330d/exports-plus) IDA Pro plugin to view Exports




***


## <a id="34ac84853604a7741c61670f2a075d20"></a>TaintAnalysis&&SymbolicExecution


- [**924**Star][13d] [OCaml] [airbus-seclab/bincat](https://github.com/airbus-seclab/bincat) Binary code static analyser, with IDA integration. Performs value and taint analysis, type reconstruction, use-after-free and double-free detection
    - Also In Section: [Tools/Structure&&Class/NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**863**Star][2y] [C++] [illera88/ponce](https://github.com/illera88/ponce) IDA 2016 plugin contest winner! Symbolic Execution just one-click away!
- [**22**Star][3m] [Py] [jonathansalwan/x-tunnel-opaque-predicates](https://github.com/jonathansalwan/x-tunnel-opaque-predicates) IDA+Triton plugin in order to extract opaque predicates using a Forward-Bounded DSE. Example with X-Tunnel.
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |


***


## <a id="9dcc6c7dd980bec1f92d0cc9a2209a24"></a>string


- [**1351**Star][2m] [Py] [fireeye/flare-floss](https://github.com/fireeye/flare-floss) FireEye Labs Obfuscated String Solver - Automatically extract obfuscated strings from malware.
    - Also In Section: [Tools/DeObfuscate](#7199e8787c0de5b428f50263f965fda7) |
    - [floss](https://github.com/fireeye/flare-floss/tree/master/floss) 
    - [IDA插件](https://github.com/fireeye/flare-floss/blob/master/scripts/idaplugin.py) 
- [**362**Star][1m] [Py] [l4ys/lazyida](https://github.com/l4ys/lazyida) Make your IDA Lazy!
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |[Tools/Vul/NoCategory](#385d6777d0747e79cccab0a19fa90e7e) |
        <details>
        <summary>View Details</summary>


        ### 功能
        - 快速移除函数返回类型
        - 数据格式(format)快速转换
        - 扫描字符串格式化漏洞
        - 双击跳转vtable函数
        - 快捷键: w/c/v
        </details>


- [**178**Star][14d] [Py] [joxeankoret/idamagicstrings](https://github.com/joxeankoret/idamagicstrings) An IDA Python script to extract information from string constants.
- [**130**Star][2y] [Py] [comsecuris/ida_strcluster](https://github.com/comsecuris/ida_strcluster) extending IDA's string navigation capabilities
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |
- [**98**Star][1y] [Py] [darx0r/stingray](https://github.com/darx0r/stingray) IDAPython plugin for finding function strings recursively
    - Also In Section: [Tools/Nav&&QuickAccess&&Graph&&Image/NoCategory](#c5b120e1779b928d860ad64ff8d23264) |[Tools/Function/Nav&&Search](#e4616c414c24b58626f834e1be079ebc) |
- [**45**Star][5y] [Py] [kyrus/ida-translator](https://github.com/kyrus/ida-translator) A plugin for IDA Pro that assists in decoding arbitrary character sets in an IDA Pro database into Unicode, then automatically invoking a web-based translation service (currently Google Translate) to translate that foreign text into English.
- [**4**Star][3y] [C#] [andreafioraldi/idagrabstrings](https://github.com/andreafioraldi/idagrabstrings) IDAPython plugin to search strings in a specified range of addresses and map it to a C struct
    - Also In Section: [Tools/Structure&&Class/NoCategory](#fa5ede9a4f58d4efd98585d3158be4fb) |
- [**4**Star][7m] [C] [lacike/gandcrab_string_decryptor](https://github.com/lacike/gandcrab_string_decryptor) IDC script for decrypting strings in the GandCrab v5.1-5.3
    - Also In Section: [Tools/SpecificTarget/MalwareFamily](#841d605300beba45c3be131988514a03) |


***


## <a id="06d2caabef97cf663bd29af2b1fe270c"></a>encrypt&&decrypt


- [**424**Star][23d] [Py] [polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara) IDA pro plugin to find crypto constants (and more)
    - Also In Section: [Tools/Signature(FLIRT...)&&Diff&&Match/Yara](#46c9dfc585ae59fe5e6f7ddf542fb31a) |
- [**122**Star][1m] [Py] [you0708/ida](https://github.com/you0708/ida) IDA related stuff
    - [IDA主题](https://github.com/you0708/ida/tree/master/theme) 
    - [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) IDA FindCrypt/FindCrypt2 插件的Python版本
- [**41**Star][7y] [C++] [vlad902/findcrypt2-with-mmx](https://github.com/vlad902/findcrypt2-with-mmx) IDA Pro findcrypt2 plug-in with MMX AES instruction finding support


# <a id="35f8efcff18d0449029e9d3157ac0899"></a>TODO


- Add more tools and posts


# <a id="18c6a45392d6b383ea24b363d2f3e76b"></a>Video&&Post


***


## <a id="4187e477ebc45d1721f045da62dbf4e8"></a>NoCategory


- 2019.10 [amossys] [Exploring Hex-Rays microcode](https://blog.amossys.fr/stage-2019-hexraysmicrocode.html)
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
- 2017.05 [repret] [Improving Coverage Guided Fuzzing, Using Static Analysis](https://repret.wordpress.com/2017/05/01/improving-coverage-guided-fuzzing-using-static-analysis/)
- 2017.04 [osandamalith] [Executing Shellcode Directly](https://osandamalith.com/2017/04/11/executing-shellcode-directly/)
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
- 2013.06 [trustwave_SpiderLabs_Blog] [Debugging Android Libraries using IDA](https://www.trustwave.com/Resources/SpiderLabs-Blog/Debugging-Android-Libraries-using-IDA/)
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
- 2015.07 [djmanilaice] [Pycharm for your IDA development](http://djmanilaice.blogspot.com/2015/07/pycharm-for-your-ida-development.html)
- 2015.07 [djmanilaice] [Auto open dlls and exe in current directory for IDA](http://djmanilaice.blogspot.com/2015/07/auto-open-dlls-and-exe-in-current.html)


***


## <a id="0b3e1936ad7c4ccc10642e994c653159"></a>Malware


- 2019.04 [360_anquanke_learning] [两种姿势批量解密恶意驱动中的上百条字串](https://www.anquanke.com/post/id/175964/)
- 2019.03 [cyber] [Using IDA Python to analyze Trickbot](https://cyber.wtf/2019/03/22/using-ida-python-to-analyze-trickbot/)
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
- 2012.06 [trustwave_SpiderLabs_Blog] [Defeating Flame String Obfuscation with IDAPython](https://www.trustwave.com/Resources/SpiderLabs-Blog/Defeating-Flame-String-Obfuscation-with-IDAPython/)


***


## <a id="04cba8dbb72e95d9c721fe16a3b48783"></a>Series-LabelessIntroduction


- 2018.10 [checkpoint] [Labeless Part 6: How to Resolve Obfuscated API Calls in the Ngioweb Proxy Malware - Check Point Research](https://research.checkpoint.com/labeless-part-6-how-to-resolve-obfuscated-api-calls-in-the-ngioweb-proxy-malware/)
- 2018.10 [checkpoint] [Labeless Part 5: How to Decrypt Strings in Boleto Banking Malware Without Reconstructing Decryption Algorithm. - Check Point Research](https://research.checkpoint.com/labeless-part-5-how-to-decrypt-strings-in-boleto-banking-malware-without-reconstructing-decryption-algorithm/)
- 2018.10 [checkpoint] [Labeless Part 4: Scripting - Check Point Research](https://research.checkpoint.com/labeless-part-4-scripting/)
- 2018.08 [checkpoint] [Labeless Part 3: How to Dump and Auto-Resolve WinAPI Calls in LockPos Point-of-Sale Malware - Check Point Research](https://research.checkpoint.com/19558-2/)
- 2018.08 [checkpoint] [Labeless Part 2: Installation - Check Point Research](https://research.checkpoint.com/installing-labeless/)
- 2018.08 [checkpoint] [Labeless Part 1: An Introduction - Check Point Research](https://research.checkpoint.com/labeless-an-introduction/)


***


## <a id="1a2e56040cfc42c11c5b4fa86978cc19"></a>Series-ReversingWithIDAFromScrach


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


## <a id="e838a1ecdcf3d068547dd0d7b5c446c6"></a>Series-UsingIDAPythonToMakeYourLifeEasier


### <a id="7163f7c92c9443e17f3f76cc16c2d796"></a>Original


- 2016.06 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/unit42-using-idapython-to-make-your-life-easier-part-6/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-5/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-4/)
- 2016.01 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-3/)
- 2015.12 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-2/)
- 2015.12 [paloaltonetworks] [Using IDAPython to Make Your Life Easie](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/)


### <a id="fc62c644a450f3e977af313edd5ab124"></a>ZH


- 2016.01 [freebuf] [IDAPython：让你的生活更美好（五）](http://www.freebuf.com/articles/system/93440.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（四）](http://www.freebuf.com/articles/system/92505.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（三）](http://www.freebuf.com/articles/system/92488.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（二）](http://www.freebuf.com/sectool/92168.html)
- 2016.01 [freebuf] [IDAPython：让你的生活更美好（一）](http://www.freebuf.com/sectool/92107.html)




***


## <a id="8433dd5df40aaf302b179b1fda1d2863"></a>Series-ReversingCCodeWithIDA


- 2019.01 [ly0n] [Reversing C code with IDA part V](https://paumunoz.tech/2019/01/12/reversing-c-code-with-ida-part-v/)
- 2019.01 [ly0n] [Reversing C code with IDA part IV](https://paumunoz.tech/2019/01/07/reversing-c-code-with-ida-part-iv/)
- 2019.01 [ly0n] [Reversing C code with IDA part III](https://paumunoz.tech/2019/01/02/reversing-c-code-with-ida-part-iii/)
- 2018.12 [ly0n] [Reversing C code with IDA part II](https://paumunoz.tech/2018/12/31/reversing-c-code-with-ida-part-ii/)
- 2018.01 [ly0n] [Reversing C code with IDA part I](https://paumunoz.tech/2018/01/11/reversing-c-code-with-ida-part-i/)


***


## <a id="3d3bc775abd7f254ff9ff90d669017c9"></a>Tool&&Plugin&&Script


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
- 2018.06 [dougallj] [Writing a Hex-Rays Plugin: VMX Intrinsics](https://dougallj.wordpress.com/2018/06/04/writing-a-hex-rays-plugin-vmx-intrinsics/)
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
- 2017.06 [reverse_archives] [EFI Swiss Knife – An IDA plugin to improve (U)EFI reversing](https://reverse.put.as/2017/06/13/efi-swiss-knife-an-ida-plugin-to-improve-uefi-reversing/)
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


## <a id="ea11818602eb33e8b165eb18d3710965"></a>Translate-TheIDAProBook


- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book 第六章](https://bbs.pediy.com/thread-75632.htm)
- 2008.10 [pediy_new_digest] [[翻译]（20081030更新）The IDA Pro Book 第12章：使用FLIRT签名识别库](https://bbs.pediy.com/thread-75422.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第二章)](https://bbs.pediy.com/thread-74943.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro book 第5章---IDA DATA DISPLAY](https://bbs.pediy.com/thread-74838.htm)
- 2008.10 [pediy_new_digest] [[翻译]The IDA Pro Book(第一章)](https://bbs.pediy.com/thread-74564.htm)


***


## <a id="ec5f7b9ed06500c537aa25851a3f2d3a"></a>Translate-ReverseEngineeringCodeWithIDAPro


- 2009.01 [pediy_new_digest] [[原创]Reverse Engineering Code with IDA Pro第七章中文译稿](https://bbs.pediy.com/thread-80580.htm)
- 2008.06 [pediy_new_digest] [[翻译]Reverse Engineering Code with IDA Pro(第一、二章)](https://bbs.pediy.com/thread-66010.htm)


***


## <a id="d8e48eb05d72db3ac1e050d8ebc546e1"></a>REPractice


- 2019.06 [devco] [破密行動: 以不尋常的角度破解 IDA Pro 偽隨機數](https://devco.re/blog/2019/06/21/operation-crack-hacking-IDA-Pro-installer-PRNG-from-an-unusual-way/)
- 2019.04 [venus_seebug] [使用 IDA Pro 的 REobjc 模块逆向 Objective-C 二进制文件](https://paper.seebug.org/887/)
- 2018.11 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting - Part 2](http://www.somersetrecon.com/blog/2018/8/2/idapython-part-2)
- 2018.07 [360_anquanke_learning] [如何使用 IDAPython 寻找漏洞](https://www.anquanke.com/post/id/151898/)
- 2018.07 [somersetrecon] [Introduction to IDAPython for Vulnerability Hunting](http://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting)
- 2018.03 [duo_blog_duo_labs] [Reversing Objective-C Binaries With the REobjc Module for IDA Pro](https://duo.com/blog/reversing-objective-c-binaries-with-the-reobjc-module-for-ida-pro)
- 2006.05 [pediy_new_digest] [Themida v1008 驱动程序分析,去除花指令的 IDA 文件](https://bbs.pediy.com/thread-25836.htm)


# Contribute
Contents auto exported by Our System, please raise Issue if you have any question.