#include "MyDebuger.h"
#include "ErrorReport.h"
#include <stdio.h>
#include "ProcessOperating.h"
#include <algorithm>
#include <fstream>

MyDebuger::MyDebuger(std::string strApp)
    : m_strApp(strApp)
{
    m_si.cb = sizeof(STARTUPINFO);

    // 创建进程
    char buf[MAX_PATH] { 0 };
    strncpy(buf, m_strApp.c_str(), m_strApp.length());
    if (ProcessOperating::CreateProcess(buf, /*DEBUG_PROCESS*/ DEBUG_ONLY_THIS_PROCESS, m_si, m_pi)) {
        // 进程创建成功
        m_IsStart = true;

        // 初始化反汇编引擎
        ZydisDecoderInit(&m_Decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
    } else {
        // 进程创建失败
        ErrorReport::Report("CreateProcess");
        m_IsStart = false;
    }
}

MyDebuger::~MyDebuger()
{
}

void MyDebuger::Work()
{
    while (m_IsStart) {
        m_dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
        // 等待调试事件
        WaitForDebugEvent(&m_DebugEv, INFINITE);

        // 判断调试事件编码，并处理
        switch (m_DebugEv.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT: // 异常
            m_dwContinueStatus = OnDebugExceptionEvent();
            break;

        case CREATE_THREAD_DEBUG_EVENT: // 创建线程
            m_dwContinueStatus = OnCreateThreadEvent();
            break;

        case CREATE_PROCESS_DEBUG_EVENT:    // 创建进程
            m_dwContinueStatus = OnCreateProcessEvent();
            break;

        case EXIT_THREAD_DEBUG_EVENT:   // 退出线程
            m_dwContinueStatus = OnExitThreadEvent();
            break;

        case EXIT_PROCESS_DEBUG_EVENT:  // 退出进程
            m_dwContinueStatus = OnExitProcessEvent();
            break;

        case LOAD_DLL_DEBUG_EVENT:  // 加载DLL
            m_dwContinueStatus = OnLoadDllEvent();
            break;

        case UNLOAD_DLL_DEBUG_EVENT:    // 卸载DLL
            m_dwContinueStatus = OnUnloadDLLEvent();
            break;

        case OUTPUT_DEBUG_STRING_EVENT: // OutputString输出
            // TODO: 不处理
            break;

        case RIP_EVENT: // RIP
            // TODO: 不处理
            break;

        default:
            break;
        }

        // 继续执行
        ContinueDebugEvent(m_DebugEv.dwProcessId, m_DebugEv.dwThreadId, m_dwContinueStatus);
    }
}

DWORD MyDebuger::OnDebugExceptionEvent()
{
    DWORD dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED/*DBG_CONTINUE*/;

    // 判断异常编码并处理
    switch (m_DebugEv.u.Exception.ExceptionRecord.ExceptionCode) {
    case EXCEPTION_ACCESS_VIOLATION:    // 内存访问异常
        dwContinueStatus = OnExceptionAccessViolation();
        break;

    case EXCEPTION_BREAKPOINT:  // 断点异常
        dwContinueStatus = OnExceptionBreakPoint();
        break;

    case EXCEPTION_DATATYPE_MISALIGNMENT:
        // TODO: 不处理
        break;

    case EXCEPTION_SINGLE_STEP: // 单步异常
        dwContinueStatus = OnExceptionSingleStep();
        break;

    case DBG_CONTROL_C:
        // TODO: 不处理
        break;

    default:
        break;
    }

    return dwContinueStatus;
}

DWORD MyDebuger::OnCreateThreadEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 加入到链表中
    m_ThreadList.push_back(THREAD_ITEM({ m_DebugEv.u.CreateThread.hThread, m_DebugEv.u.CreateThread.lpThreadLocalBase,
                            m_DebugEv.u.CreateThread.lpStartAddress }));

    return dwContinueStatus;
}

DWORD MyDebuger::OnCreateProcessEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 是否是当前被调试的进程
    if (m_DebugEv.dwProcessId == m_pi.dwProcessId) {
        printf("\tWelcome to MyDebuger!\n       输入 < ? > 查看帮助页面\n\n");

        AppendModule(m_DebugEv.u.CreateProcessInfo.hFile);

        // 设置入口点为一次性断点
        AddBP(m_DebugEv.u.CreateProcessInfo.lpStartAddress, true);

        // 打印信息
        printf("调试程序：%s\n", m_ModuleList.front().ModulePath.c_str());
        printf("入口地址: %p  模块基址: %p\n\n", m_DebugEv.u.CreateProcessInfo.lpStartAddress, m_DebugEv.u.CreateProcessInfo.lpBaseOfImage);
    }

    return dwContinueStatus;
}

DWORD MyDebuger::OnExitThreadEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 遍历线程链表
    auto iter = m_ThreadList.begin();
    while (iter != m_ThreadList.end()) {
        // 将当前退出的线程从链表中移除
        if (::GetThreadId(iter->hThread) == m_DebugEv.dwThreadId) {
            m_ThreadList.erase(iter);
            break;
        }
        ++iter;
    }

    return dwContinueStatus;
}

DWORD MyDebuger::OnExitProcessEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 是否是当前被调试的进程
    if (m_DebugEv.dwProcessId == m_pi.dwProcessId) {
        m_IsStart = false;
        ::CloseHandle(m_pi.hProcess);
        ::CloseHandle(m_pi.hThread);
    }
    return dwContinueStatus;
}

DWORD MyDebuger::OnLoadDllEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 添加到链表中
    AppendModule(m_DebugEv.u.LoadDll.hFile, true);

    return dwContinueStatus;
}

DWORD MyDebuger::OnUnloadDLLEvent()
{
    DWORD dwContinueStatus = DBG_CONTINUE;

    // 遍历模块链表
    auto iter = m_ModuleList.begin();
    while (iter != m_ModuleList.end()) {
        // 将当前卸载的DLL从链表中移除
        if (iter->hModule == (HANDLE)m_DebugEv.u.UnloadDll.lpBaseOfDll) {
            m_ModuleList.erase(iter);
            break;
        }
        ++iter;
    }

    return dwContinueStatus;
}

DWORD MyDebuger::OnExceptionBreakPoint()
{
    // 获取当前异常的地址
    m_CurrentAddr = (ZyanU64)m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;

    // 判断是否是系统断点
    if (m_IsSysBP) {
        m_IsSysBP = false;
        // 判断异常地址是否是主入口点
        if (m_CurrentAddr != (DWORD)m_ModuleList.front().hModule) {
            return DBG_CONTINUE;
        }
    }

    // 退回到异常发送处
    ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context);
    m_Context.Eip = (DWORD)m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;
    ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context);

    // 显示寄存器
    ShowRegister();

    // 获取该地址处的代码指令数据
    ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));

    // 反汇编显示一行
    ShowDisassembly(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 1);

    // 遍历链表，查找当前的断点节点
    auto iter = m_BPList.begin();
    while (iter != m_BPList.end()) {
        if (iter->BPAddr == m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress) {
            // 还原指令
            ProcessOperating::WriteProcessMemory(m_DebugEv.dwProcessId, iter->BPAddr, &iter->OldCode, sizeof(iter->OldCode));

            // 判断是否是一次性断点
            if (iter->IsOnce) {
                // 删除节点
                iter = m_BPList.erase(iter);
                continue;
            } else {
                // 加入到还原链表中
                m_BPReductionList.push_back(*iter);
            }
        }
        ++iter;
    }

    // 检测自动追踪是否开启
    if (m_IsAutoTrack) {
        // 检查跟踪是否未开启
        if (!m_IsTrack) {
            // 检查异常地址是否是跟踪的起始地址
            if (m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress == m_AutoTrackParam.StartAddr) {
                // 开始跟踪
                m_IsTrack = true;
                m_IsRun = false;    // 禁用g命令
                SetSingleStep();    // 设置单步

                //读取该地址的汇编数据
                ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));

                //显示这一行触发异常的汇编
                ShowDisassembly(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 1);

                return DBG_CONTINUE;
            }
        } else {
            // 停止跟踪
            m_IsTrack = false;
            m_IsAutoTrack = false;

            printf("触发断点，跟踪停止，Dump文件：%p-%p.txt\n", m_AutoTrackParam.StartAddr, m_AutoTrackParam.EndAddr);
            char buf[MAX_PATH] { 0 };
            sprintf(buf, "%p-%p.txt", m_AutoTrackParam.StartAddr, m_AutoTrackParam.EndAddr);
            // dump信息
            DumpTrackInfo(buf);
        }
    }

    return GetCmdLine();
}

DWORD MyDebuger::OnExceptionAccessViolation()
{
    MEMORY_BASIC_INFORMATION mbi;
    // 查询内存属性
    ProcessOperating::VirtualQueryEx(m_DebugEv.dwProcessId, (PVOID)m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1], mbi);

    unsigned int PageIndex;//分页索引

    // 检查是否存在分页(是否是自己断点的分页)
    if (IsExistsMemPage(mbi.BaseAddress, &PageIndex)) {
        unsigned int BPIndex;//断点索引

        // 检查是否存在断点(是否是自己下的断点)
        if (IsExistMemBP((PVOID)m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1], &BPIndex)) {
            // 检查触发断点类型是否一致
            if (m_MemBPList[BPIndex].MemBPType == m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[0]) {
               

                switch (m_MemBPList[BPIndex].MemBPType) {
                case TYPE_MEMBP::MEMBP_READ:    // 读
                    printf("内存访问：%p\n", (PVOID)m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1]);
                    break;
                case TYPE_MEMBP::MEMBP_WRITE:   // 写
                    printf("内存写入：%p\n", (PVOID)m_DebugEv.u.Exception.ExceptionRecord.ExceptionInformation[1]);
                    break;
                }

                // 显示寄存器
                ShowRegister();

                // 读取该地址的汇编数据
                ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId,
                    m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress, m_MemoryData, sizeof(m_MemoryData));

                // 显示这一行触发异常的汇编
                ShowDisassembly((ZyanU64)m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress, m_MemoryData, sizeof(m_MemoryData), 1);

                // 还原原始内存属性保护
                if (ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, m_MemBPPageList[PageIndex].StartAddr,
                    m_MemBPPageList[PageIndex].dwSize, m_MemBPPageList[PageIndex].dwOldProtect)) {
                    //添加还原内存分页链表
                    m_MemBPPageReductionList.push_back(m_MemBPPageList[PageIndex]);
                } else {
                    printf("内存断点，还原原始内存属性保护失败\n");
                }

                return GetCmdLine();
            }
        }

        // 还原原始内存属性保护
        if (ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, m_MemBPPageList[PageIndex].StartAddr,
            m_MemBPPageList[PageIndex].dwSize, m_MemBPPageList[PageIndex].dwOldProtect)) {
            // 添加还原内存分页链表
            m_MemBPPageReductionList.push_back(m_MemBPPageList[PageIndex]);

            // 设置单步(用于还原内存断点)
            SetSingleStep();
            m_IsRun = true;//设置g命令运行
            return DBG_CONTINUE;
        } else {
            printf("内存断点，还原原始内存属性保护失败\n");
            return GetCmdLine();
        }
    }
    printf("未知异常\n");

    // 读取该地址的汇编数据
    ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress,
        m_MemoryData, sizeof(m_MemoryData));

    // 显示这一行触发异常的汇编
    ShowDisassembly((ZyanU64)m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress, m_MemoryData, sizeof(m_MemoryData), 1);
    return GetCmdLine();
}

DWORD MyDebuger::OnExceptionSingleStep()
{
    // 获取异常地址
    m_CurrentAddr = (ZyanU64)m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress;

    // 还原断点、硬件断点、内存断点
    if (!m_BPReductionList.empty() || !m_HBPReductionList.empty() || !m_MemBPPageReductionList.empty()) {
        // 还原断点
        for (auto &item : m_BPReductionList) {
            ProcessOperating::WriteProcessMemory(m_DebugEv.dwProcessId, item.BPAddr, &item.NEwCode, sizeof(item.NEwCode));
        }
        m_BPReductionList.clear();

        // 还原硬件断点
        for (auto &item : m_HBPReductionList) {
            // 获取线程环境上下文
            if (ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
                DR7 Dr7;
                Dr7.Dr7 = m_Context.Dr7;
                // 重新设置断点 根据寄存器ID
                switch (item.DrId) {
                case 0:                                     // Dr0
                    m_Context.Dr0 = (DWORD)item.HBPAddr;    // 设置地址
                    Dr7.L0 = 1;                             // 设置全局
                    Dr7.RW0 = item.HBPType;                 // 设置类型
                    Dr7.LEN0 = item.HBPLen;                 // 设置长度
                    break;
                case 1:                                     // Dr1                                   
                    m_Context.Dr1 = (DWORD)item.HBPAddr;    // 设置地址
                    Dr7.L1 = 1;                             // 设置全局
                    Dr7.RW1 = item.HBPType;                 // 设置类型
                    Dr7.LEN1 = item.HBPLen;                 // 设置长度
                    break;
                case 2:                                     // Dr2                                   
                    m_Context.Dr2 = (DWORD)item.HBPAddr;    // 设置地址
                    Dr7.L2 = 1;                             // 设置全局
                    Dr7.RW2 = item.HBPType;                 // 设置类型
                    Dr7.LEN2 = item.HBPLen;                 // 设置长度
                    break;
                case 3:                                     // Dr3                                   
                    m_Context.Dr3 = (DWORD)item.HBPAddr;    // 设置地址
                    Dr7.L3 = 1;                             // 设置全局
                    Dr7.RW3 = item.HBPType;                 // 设置类型
                    Dr7.LEN3 = item.HBPLen;                 // 设置长度
                    break;
                }

                m_Context.Dr7 = Dr7.Dr7;

                // 设置线程上下文环境
                ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context);
            }
        }
        m_HBPReductionList.clear();

        // 还原内存断点
        for (auto &item : m_MemBPPageReductionList) {
            ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, item.StartAddr, item.dwSize, item.dwNewProtect);
        }
        m_MemBPPageReductionList.clear();
    }

    if (OnExceptionHardwareBreakPoint()) {
        m_IsRun = false;    // 禁用g命令
    }

    if (!m_IsRun) {
        //显示寄存器
        ShowRegister();

        //读取该地址的汇编数据
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));

        //显示这一行触发异常的汇编
        ShowDisassembly(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 1);
    }


    // 检查自动跟踪是否开启
    if (m_IsAutoTrack) {
        // 跟踪是否开启
        if (m_IsTrack) {
            // 如果异常地址不是跟踪的结束地址，继续跟踪
            if (m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress != m_AutoTrackParam.EndAddr) {
                SetSingleStep();
                return DBG_CONTINUE;
            } else {
                // 停止跟踪
                m_IsTrack = false;
                m_IsAutoTrack = false;
                printf("跟踪完成，Dump文件：%p-%p.txt\n", m_AutoTrackParam.StartAddr, m_AutoTrackParam.EndAddr);
                char buf[MAX_PATH] { 0 };
                sprintf(buf, "%p-%p.txt", m_AutoTrackParam.StartAddr, m_AutoTrackParam.EndAddr);
                // dump信息
                DumpTrackInfo(buf);
            }
        }
    }


    // 检查是否g运行
    if (m_IsRun) {
        m_IsRun = false;
        return DBG_CONTINUE;
    }

    return GetCmdLine();
}

DWORD MyDebuger::OnExceptionHardwareBreakPoint()
{
    // 硬件断点不为空
    if (!m_HBPList.empty()) {
        for (auto &item : m_HBPList) {
            // 检查是否是硬件断点
            if (item.HBPAddr == m_DebugEv.u.Exception.ExceptionRecord.ExceptionAddress) {
                printf("硬件断点：%p\n", item.HBPAddr);
                // 获取线程上下文环境
                if (ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
                    DR7 Dr7;
                    Dr7.Dr7 = m_Context.Dr7;

                    // 还原硬件断点
                    switch (item.DrId) {
                    case 0:                 // DR0
                        m_Context.Dr0 = 0;  // 清空地址
                        Dr7.L0 = 0;         // 清空全局标志
                        Dr7.RW0 = 0;        // 清空类型
                        Dr7.LEN0 = 0;       // 清空长度
                        break;
                    case 1:                 // DR1
                        m_Context.Dr1 = 0;  // 清空地址
                        Dr7.L1 = 0;         // 清空全局标志
                        Dr7.RW1 = 0;        // 清空类型
                        Dr7.LEN1 = 0;       // 清空长度
                        break;
                    case 2:                 // DR2
                        m_Context.Dr2 = 0;  // 清空地址
                        Dr7.L2 = 0;         // 清空全局标志
                        Dr7.RW2 = 0;        // 清空类型
                        Dr7.LEN2 = 0;       // 清空长度
                        break;
                    case 3:                 // DR3
                        m_Context.Dr3 = 0;  // 清空地址
                        Dr7.L3 = 0;         // 清空全局标志
                        Dr7.RW3 = 0;        // 清空类型
                        Dr7.LEN3 = 0;       // 清空长度
                        break;
                    }

                    m_Context.Dr7 = Dr7.Dr7;

                    // 设置线程上下文环境
                    if (ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
                        m_HBPReductionList.push_back(item);
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

DWORD MyDebuger::GetCmdLine()
{
    DWORD dwContinueStatus = DBG_CONTINUE;
    char buf[CHAR_MAX] { 0 };

    while (true) {
        std::string cmd;
        if (m_CmdLineQueue.empty()) {
            // 命令队列为空，读取用户输入
            printf("MyDebuger$ ");
            fgets(buf, sizeof(buf), stdin);
            // 全部转换为小写
            _strlwr(buf);
            cmd = buf;
        } else {
            // 从命令队列中拿命令
            cmd = m_CmdLineQueue.front();
            m_CmdLineQueue.pop();
            strncpy(buf, cmd.c_str(), cmd.length());
        }

        // 开始解析命令
        if (strncmp(buf, "?", 1) == 0) {
            // 查看帮助
            ShowHelp();
        } else if (strncmp(buf, "u", 1) == 0) {
            // 查看反汇编 u [address]
            OnCmdU(buf);
        } else if (strncmp(buf, "dd", 2) == 0) {
            // 查看内存 dd [address]
            OnCmdDD(buf);
        } else if (strncmp(buf, "r", 1) == 0) {
            // 显示寄存器
            ShowRegister();
        } else if (strncmp(buf, "ml", 2) == 0) {
            // 显示模块
            ShowModule();
        } else if (strncmp(buf, "q", 1) == 0) {
            // 退出
            QuitDebug();
        } else if (strncmp(buf, "ls", 2) == 0) {
            // 导入脚本
            if (OnCmdLS(buf)) {
                continue;
            }
        } else if (strncmp(buf, "es", 2) == 0) {
            // 导出脚本
            ExportScript();
        } else if (strncmp(buf, "e", 1) == 0) {
            // 修改内存数据
            if (OnCmdE(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bpl", 3) == 0) {
            // 显示断点列表
            ShowBPList();
        } else if (strncmp(buf, "bpc", 3) == 0) {
            // 删除断点
            if (OnCmdBPC(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bp", 2) == 0) {
            // 下断点
            if (OnCmdBP(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bml", 3) == 0) {
            // 显示内存断点列表
            ShowMemBPList();
        } else if (strncmp(buf, "bmpl", 4) == 0) {
            // 显示分页内存断点列表
            ShowMemBPList(true);
        } else if (strncmp(buf, "bmc", 3) == 0) {
            // 删除内存断点
            if (OnCmdBMC(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bm", 2) == 0) {
            // 下内存断点
            if (OnCmdBM(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bhl", 3) == 0) {
            // 显示硬件断点列表
            ShowHBPList();
        } else if (strncmp(buf, "bhc", 3) == 0) {
            // 删除硬件断点
            if (OnCmdBHC(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "bh", 2) == 0) {
            // 下硬件断点
            if (OnCmdBH(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
            }
        } else if (strncmp(buf, "g", 1) == 0) {
            // g运行
            if (OnCmdG(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
                break;
            }
        } else if (strncmp(buf, "trace", 5) == 0) {
            // 跟踪
            OnCmdTRACE(buf);
        } else if (strncmp(buf, "t", 1) == 0) {
            // 单步步入
            if (OnCmdT(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
                break;
            }
        } else if (strncmp(buf, "p", 1) == 0) {
            // 单步步过
            if (OnCmdP(buf)) {
                // 记录命令
                m_CmdRecordList.push_back(cmd);
                break;
            }
        } else if(strncmp(buf, "dump", 4) == 0) {
            // dump内存
            if(!OnCmdDUMP(buf)) {
                printf("Dump失败\n");
            }
        } else {  // 没有命令匹配
            printf("命令错误，请输入< ? >查看帮助\n");
        }
    }

    return dwContinueStatus;
}

bool MyDebuger::AddBP(void *BPAddr, bool IsOnecBP)
{
    int ret = false;
    // 断点是否存在
    if (IsExistsBP(BPAddr)) {    
        printf("地址: %p, 断点已经存在\n", BPAddr);
        return ret;
    }

    if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, BPAddr)) {   // 检查地址是否有效
        // 检查其他断点
        if(IsExistsOtherBreakPoint(BPAddr)) {
            printf("地址：%p，存在其他断点\n", BPAddr);
            return ret;
        }

        // 读原始的代码
        BYTE OldCode;   // 原始代码
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, BPAddr, &OldCode, sizeof(BYTE));

        // 写入断点
        BYTE NewCode = 0xcc;   // 新代码
        if (ProcessOperating::WriteProcessMemory(m_DebugEv.dwProcessId, BPAddr, &NewCode, sizeof(BYTE))) {
            // 加入链表中
            m_BPList.push_back(BP_ITEM({ BPAddr, OldCode, NewCode, IsOnecBP }));
            ret = true;
        } else {
            printf("地址: %p, 断点失败\n", BPAddr);
        }
    } else {
        printf("地址: %p, 断点失败，访问无效地址\n", BPAddr);
    }
    return ret;
}

bool MyDebuger::DelBP(unsigned number)
{
    if (m_BPList.empty() || number >= m_BPList.size()) {
        return false;   // 链表为空或者编号大于链表的长度
    }
    // 还原数据
    ProcessOperating::WriteProcessMemory(m_DebugEv.dwProcessId, m_BPList[number].BPAddr,
        &m_BPList[number].OldCode, sizeof(m_BPList[number].OldCode));
    // 删除节点
    m_BPList.erase(m_BPList.begin() + number);
    return true;
}

bool MyDebuger::AddMemBP(void *BPAddr, unsigned BPSize, TYPE_MEMBP BPType)
{
    // 检查其他断点
    if (IsExistsOtherBreakPoint(BPAddr)) {
        printf("地址：%p，存在其他断点\n", BPAddr);
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    // 查询内存
    if (!ProcessOperating::VirtualQueryEx(m_DebugEv.dwProcessId, BPAddr, mbi)) {
        printf("地址：%p，添加内存断点失败\n", BPAddr);
        return false;
    }

    // 检查是否跨越分页
    SYSTEM_INFO SysInfo;
    ::GetSystemInfo(&SysInfo);
    if ((DWORD64)mbi.BaseAddress + SysInfo.dwPageSize < (DWORD64)BPAddr + BPSize) {
        printf("暂不支持跨分页断点\n");
        return false;
    }

    if (!IsExistsMemPage(mbi.BaseAddress)) {
        // 如果分页断点不存在
        if (!ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, mbi.BaseAddress, SysInfo.dwPageSize, PAGE_NOACCESS)) {
            printf("地址：%p，添加内存断点失败\n", BPAddr);
            return false;
        }

        // 加入链表
        m_MemBPPageList.push_back(MEM_PAGE_ITEM({ mbi.BaseAddress, SysInfo.dwPageSize, mbi.Protect, PAGE_NOACCESS }));
    }

    // 检查设置断点是否存在
    if (IsExistMemBP(BPAddr)) {
        printf("地址：%p，已经存在此内存断点", BPAddr);
        return false;
    }

    // 加入链表
    m_MemBPList.push_back(MEMBP_ITEM({ BPAddr, BPSize, BPType }));
    return true;
}

bool MyDebuger::IsExistsMemPage(void *PageAddr, unsigned *Index)
{
    // 遍历分页表是否存在这个地址
    for (size_t i = 0; i < m_MemBPPageList.size(); i++) {
        if (m_MemBPPageList[i].StartAddr == PageAddr) {
            //检查返回索引ID指针是否有效
            if (Index != nullptr) {
                *Index = i; // 返回索引ID
            }
            return true;    // 存在分页地址
        }
    }
    return false;   // 不存在分页地址
}

bool MyDebuger::IsExistMemBP(void *PageAddr, unsigned *Index)
{
    // 检查这个范围内是否被下过断点，不在范围内的检查失败

    // 遍历内存断点表
    for (size_t i = 0; i < m_MemBPList.size(); i++) {
        //得到临时结束地址
        DWORD64 dwEndAddress = (DWORD64)m_MemBPList[i].MemBPAddr + m_MemBPList[i].dwSize;

        if ((DWORD64)PageAddr < dwEndAddress && (DWORD64)PageAddr >= (DWORD64)m_MemBPList[i].MemBPAddr) {
            //检查返回索引指针是否有效
            if (Index != nullptr) {
                *Index = i;
            }
            return true; //这个范围内已经存在其他断点
        }
    }
    return false;
}

bool MyDebuger::DelMemBP(unsigned number)
{
    if (m_MemBPList.empty() || number >= m_MemBPList.size()) {
        return false;   // 链表为空或者编号大于链表的长度
    }
    if (m_MemBPPageList.empty() || number >= m_MemBPPageList.size()) {
        return false;
    }
    // 删除节点
    m_MemBPList.erase(m_MemBPList.begin() + number);

    // 将分页属性设置回去
    ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, m_MemBPPageList[number].StartAddr,
        m_MemBPPageList[number].dwSize, m_MemBPPageList[number].dwOldProtect);
    m_MemBPPageList.erase(m_MemBPPageList.begin() + number);
    return true;
}

bool MyDebuger::AddHBP(void *BPAddr, TYPE_HBP HBPType, LEN_HBP HBPSize)
{
    DR7 Dr7 { 0 };
    if (m_HBPList.size() >= 4) {
        // 断点满
        printf("硬件断点不能超过4个\n");
        return false;
    }

    // 检查其他断点
    if (IsExistsOtherBreakPoint(BPAddr)) {
        printf("地址：%p，存在其他断点\n", BPAddr);
        return false;
    }

    // 获取线程上下文
    if (!ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        return false;
    }

    Dr7.Dr7 = m_Context.Dr7;
    DWORD DrId = 0;//硬件断点ID

    //设置断点地址
    if (m_Context.Dr0 == 0) {
        m_Context.Dr0 = (DWORD)BPAddr;  //设置地址
        DrId = 0;                       //设置寄存器ID
        Dr7.L0 = 1;                     //设置全局
        Dr7.RW0 = HBPType;              //设置类型
        Dr7.LEN0 = HBPSize;             //设置长度
    } else if (m_Context.Dr1 == 0) {
        m_Context.Dr1 = (DWORD)BPAddr;  //设置地址
        DrId = 1;                       //设置寄存器ID
        Dr7.L1 = 1;                     //设置全局
        Dr7.RW1 = HBPType;              //设置类型
        Dr7.LEN1 = HBPSize;             //设置长度
    } else if (m_Context.Dr2 == 0) {
        m_Context.Dr2 = (DWORD)BPAddr;  //设置地址
        DrId = 2;                       //设置寄存器ID
        Dr7.L2 = 1;                     //设置全局
        Dr7.RW2 = HBPType;              //设置类型
        Dr7.LEN2 = HBPSize;             //设置长度
    } else if (m_Context.Dr3 == 0) {
        m_Context.Dr3 = (DWORD)BPAddr;  //设置地址
        Dr7.L3 = 1;                     //设置全局
        DrId = 3;                       //设置寄存器ID
        Dr7.RW3 = HBPType;              //设置类型
        Dr7.LEN3 = HBPSize;             //设置长度
    } else {
        printf("硬件断点失败，寄存器已满\n");
        return false;
    }

    // 设置Dr7寄存器
    m_Context.Dr7 = Dr7.Dr7;
    if (!ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        printf("硬件断点失败\n");
        return false;
    }
    m_HBPList.push_back(HBP_ITEM({ DrId, BPAddr, HBPType, HBPSize }));
    return true;
}

bool MyDebuger::DelHBP(unsigned number)
{
    if (m_HBPList.empty() || number >= m_HBPList.size()) {
        return false;   // 链表为空或者编号大于链表的长度
    }

    DR7 Dr7;
    // 获取线程上下文环境
    if (!ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        return false;
    }

    Dr7.Dr7 = m_Context.Dr7;
    // 检查链表中地址对应哪个寄存器
    if (m_HBPList[number].HBPAddr == (PVOID)m_Context.Dr0) {
        m_Context.Dr0 = 0;      // 清空地址
        Dr7.L0 = 0;             // 取消全局
        Dr7.RW0 = 0;            // 去除类型
        Dr7.LEN0 = 0;           // 取消长度

    } else if (m_HBPList[number].HBPAddr == (PVOID)m_Context.Dr1) {
        m_Context.Dr1 = 0;      // 清空地址
        Dr7.L1 = 0;             // 取消全局
        Dr7.RW1 = 0;            // 去除类型
        Dr7.LEN1 = 0;           // 取消长度
    } else if (m_HBPList[number].HBPAddr == (PVOID)m_Context.Dr2) {
        m_Context.Dr2 = 0;      // 清空地址
        Dr7.L2 = 0;             // 取消全局
        Dr7.RW2 = 0;            // 去除类型
        Dr7.LEN2 = 0;           // 取消长度
    } else if (m_HBPList[number].HBPAddr == (PVOID)m_Context.Dr3) {
        m_Context.Dr3 = 0;      // 清空地址
        Dr7.L3 = 0;             // 取消全局
        Dr7.RW3 = 0;            // 去除类型
        Dr7.LEN3 = 0;           // 取消长度
    }

    m_Context.Dr7 = Dr7.Dr7;

    // 设置线程上下文环境
    if (!ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        printf("删除硬件断点失败\n");
        return false;
    }
    m_HBPList.erase(m_HBPList.begin() + number);

    return true;
}

bool MyDebuger::IsExistsBP(void *BPAddr)
{
    for (auto &item : m_BPList) {
        if (item.BPAddr == BPAddr) {
            // 断点已经存在
            return true;
        }
    }
    return false;
}

void MyDebuger::AppendModule(HANDLE hFile, bool IsLoadDLl)
{
    IMAGE_DOS_HEADER ImageDosHeader;
    IMAGE_NT_HEADERS32 ImageNtHeaders32;
    char buf[MAX_PATH] { 0 };
    // 获取主模块路径
    ::GetFinalPathNameByHandleA(hFile, buf, sizeof(buf), VOLUME_NAME_DOS);
    std::string path = (char *)buf + 4; // 过滤开头的 \\?\

    // 获取模块名
    std::string name = path.substr(path.find_last_of("\\") + 1);

    if (IsLoadDLl) {
        // 读DOS头
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, m_DebugEv.u.LoadDll.lpBaseOfDll,
            &ImageDosHeader, sizeof(ImageDosHeader));
        // 读Nt头
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PBYTE)m_DebugEv.u.LoadDll.lpBaseOfDll + ImageDosHeader.e_lfanew,
            &ImageNtHeaders32, sizeof(ImageNtHeaders32));
        // 保存模块信息
        m_ModuleList.push_back(MODULE_ITEM({ m_DebugEv.u.LoadDll.lpBaseOfDll,
            ImageNtHeaders32.OptionalHeader.SizeOfImage, name, path }));
    } else {
        // 读DOS头
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, m_DebugEv.u.CreateProcessInfo.lpBaseOfImage,
            &ImageDosHeader, sizeof(ImageDosHeader));
        // 读Nt头
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PBYTE)m_DebugEv.u.CreateProcessInfo.lpBaseOfImage + ImageDosHeader.e_lfanew,
            &ImageNtHeaders32, sizeof(ImageNtHeaders32));
        // 保存模块信息
        m_ModuleList.push_back(MODULE_ITEM({ m_DebugEv.u.CreateProcessInfo.lpBaseOfImage,
            ImageNtHeaders32.OptionalHeader.SizeOfImage, name, path }));
    }
}

bool MyDebuger::IsExistsModule(std::string ModuleName, unsigned *Index)
{
    for (unsigned int i = 0; i < m_ModuleList.size(); i++) {
        std::string tmp = m_ModuleList[i].ModuleName;
        std::transform(tmp.begin(), tmp.end(), tmp.begin(), tolower);
        if (ModuleName == tmp) {
            *Index = i;
            return true;
        }
    }
    return false;
}

ZyanUSize MyDebuger::ShowDisassembly(ZyanU64 runtime_address, ZyanU8 *data, ZyanUSize length, DWORD dwLine,
    bool bIsShow)
{
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

    ZydisDecodedInstruction instruction;
    ZyanUSize ZuSize = length;

    char buffer[256];
    char szBuf[256];    //格式化缓冲区

    // 遍历显示i行
    for (DWORD i = 0; i < dwLine; i++) {
        std::string record; //自动跟踪记录

        // 查找并还原断点处的指令
        for (auto &item : m_BPList) {
            if (item.BPAddr == (PVOID)runtime_address) {
                // 还原指令
                BYTE *ptr = (BYTE *)data;
                *ptr = item.OldCode;
            }
        }

        // 反汇编
        if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_Decoder, data, length, &instruction))) {
            if (bIsShow) {
                printf("%p  ", (PVOID)runtime_address); // 打印地址
            }

            ZydisFormatterFormatInstruction(&formatter, &instruction, &buffer[0], sizeof(buffer),
                runtime_address);

            // 遍历指令
            for (int i = 0; i < 8; i++) {
                if (i < instruction.length) {
                    if (bIsShow) {
                        printf("%02X ", data[i]);   // 打印机器码
                    }

                    // 是否跟踪
                    if (m_IsTrack)
                    {
                        sprintf(szBuf, "%02X ", data[i]);
                        record += szBuf;//记录字符
                    }
                } else {
                    if (bIsShow) {
                        printf("   ");
                    }

                    //是否跟踪
                    if (m_IsTrack)
                    {
                        sprintf(szBuf, "   ");
                        record += szBuf;//记录字符
                    }
                }
            }

            if (bIsShow) {
                ZYAN_PRINTF("%s\n", &buffer[0]);    // 打印指令
            }

            // 是否跟踪
            if (m_IsTrack)
            {
                sprintf(szBuf, "%s\n", &buffer[0]);
                record += szBuf;//记录字符

                //添加跟踪信息
                AppendTrackData((PVOID)runtime_address, record);
            }

            data += instruction.length;
            length -= instruction.length;
            runtime_address += instruction.length;
        }
    }
    return ZuSize - length;//返回显示大小
}

ZyanUSize MyDebuger::ShowHex(ZyanU64 ZuAddress, PBYTE pBuf, DWORD dwSize, DWORD dwLine)
{
    size_t nPos = 0;//移动点
    size_t nRemaining = 0;//剩余
    size_t nSize = 0;//大小
    size_t nLine = 0;//行数
    //检查要显示的大小是否大于16
    if (dwSize >= 16)
    {
        nSize = 16;
    } else
    {
        nSize = dwSize;
    }

    //检查是否移动到最大要显示的数据
    while (nPos < dwSize && nLine < dwLine)
    {
        printf("%p  ", (PVOID)ZuAddress);
        //显示十六禁止数组
        for (size_t i = 0; i < nSize; i++)
        {
            if (i == 8)
            {
                printf("- ");
            }

            printf("%.2X ", pBuf[nPos + i]);
        }

        //显示ASCII
        for (size_t i = 0; i < nSize; i++)
        {
            //过滤显示可见
            if ((pBuf[nPos + i] >= 32 && pBuf[nPos + i] < 128))
            {
                printf("%c", pBuf[nPos + i]);
            } else
            {
                printf(".");
            }
        }

        nPos += nSize;//移动已显示的大小
        nRemaining = dwSize - nPos;//得到剩余

        //检查剩余数据是否大于16
        if (nRemaining >= 16)
        {
            nSize = 16;
        } else
        {
            nSize = nRemaining;
        }
        ZuAddress += 16;//地址+16
        nLine++;//行数+1

        printf("\r\n");

    }

    return nLine * 16;
}

bool MyDebuger::OnCmdU(char *buf)
{
    int ret = false;
    char *s = strtok(buf, " "); // 以空格切割
    s = strtok(nullptr, "\n"); // 切掉回车换行
    if (s != nullptr) {
        // 取得地址
        m_CurrentAddr = strtoul(s, nullptr, 16);    // 以16进制
    }

    // 检查地址是否有效
    if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr)) {
        // 读取汇编指令数据
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));
        // 显示
        m_CurrentAddr += ShowDisassembly(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 10);
        ret = true;
    } else {
        printf("地址：%p，无效的地址\n", (PVOID)m_CurrentAddr);
    }
    return ret;
}

bool MyDebuger::OnCmdDD(char *buf)
{
    int ret = false;
    char *s = strtok(buf, " "); // 以空格切割
    s = strtok(nullptr, "\n"); // 切掉回车换行
    if (s != nullptr) {
        // 取得地址
        m_CurrentAddr = strtoul(s, nullptr, 16);    // 以16进制
    }

    // 检查地址是否有效
    if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr)) {
        // 读取数据
        ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));
        // 显示
        m_CurrentAddr += ShowHex(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 5);
        ret = true;
    } else {
        printf("地址：%p，无效的地址\n", (PVOID)m_CurrentAddr);
    }
    return ret;
}

bool MyDebuger::OnCmdE(char *buf)
{
    int ret = true;
    char *s = strtok(buf, " "); // 以空格切割
    s = strtok(nullptr, " ");

    if (s != nullptr) {
        //得到内存地址
        void *Addr = (void *)strtoul(s, nullptr, 16);
        s = strtok(nullptr, "\n");  // 切掉回车换行

        if (s != nullptr) {
            //检查是否输入大于3个字符
            if (strlen(s) < 3) {
                BYTE Data = (BYTE)strtoul(s, nullptr, 16);

                // 检查地址是否有效，检查修改内存属性保护
                if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, Addr)
                    && ProcessOperating::VirtualProtectEx(m_DebugEv.dwProcessId, Addr, 1, PAGE_EXECUTE_READWRITE)) {
                    if (ProcessOperating::WriteProcessMemory(m_DebugEv.dwProcessId, Addr, &Data, sizeof(Data))) {
                        ret = true;
                    }
                } else {
                    printf("地址：%p，修改失败，无效内存地址\n", Addr);
                    ret = false;
                }
            } else {
                printf("修改失败，只能修改1个字节\n");
                ret = false;
            }
        } else {
            printf("修改失败，格式错误\n");
            ret = false;
        }
    }
    return ret;
}

bool MyDebuger::OnCmdBP(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, " ");
    if (s != nullptr) {
        void *Addr = (void *)strtoul(s, nullptr, 16);
        s = strtok(nullptr, "\n");

        if (s != nullptr) {
            if (strncmp(s, "sys", 3) == 0) {
                //添加一次性断点
                return AddBP(Addr, true);
            } else {
                printf("添加断点失败,未知格式\n");
                return false;
            }
        } else {
            //添加非一次性断点
            return AddBP(Addr, false);
        }
    }
    return false;
}

bool MyDebuger::OnCmdBPC(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, "\n");
    if (s != nullptr) {
        unsigned int index = strtoul(s, nullptr, 10);
        // 删除断点
        return DelBP(index);
    } else {
        printf("删除失败，输入格式错误\n");
    }
    return false;
}

bool MyDebuger::OnCmdBMC(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, "\n");
    if (s != nullptr) {
        unsigned int index = strtoul(s, nullptr, 10);
        // 删除断点
        return DelMemBP(index);
    } else {
        printf("删除失败，格式错误\n");
    }
    return false;
}

bool MyDebuger::OnCmdBM(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, " ");
    if (s != nullptr)
    {
        //得到内存地址
        void *Addr = (void *)strtoul(s, nullptr, 16);

        s = strtok(nullptr, " ");
        if (s != nullptr) {
            //得到长度
            size_t len = strtoul(s, nullptr, 10);
            s = strtok(nullptr, " ");
            if (s != nullptr) {
                //检查地址是否有效
                if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, Addr)) {
                    if (!strncmp(s, "r", 1)) {
                        //设置只读内存断点
                        return AddMemBP(Addr, len, TYPE_MEMBP::MEMBP_READ);
                    } else if (!strncmp(s, "w", 1)) {
                        //设置写入内存断点
                        return AddMemBP(Addr, len, TYPE_MEMBP::MEMBP_WRITE);
                    }
                }
            }
        }
    }
    printf("添加内存断点失败\n");
    return false;
}

bool MyDebuger::OnCmdBH(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, " ");
    if (s != nullptr) {
        // 得到地址
        void *Addr = (void *)strtoul(s, nullptr, 16);
        s = strtok(nullptr, " ");
        if (s != nullptr) {
            if (strncmp(s, "e", 1) == 0) {
                // 添加硬件执行断点，长度必须为1Byte
                return AddHBP(Addr, TYPE_HBP::HBP_EXECUTE, LEN_HBP::HBP_LEN_1B);
            } else if (strncmp(s, "w", 1) == 0) {
                // 添加硬件写入断点
                s = strtok(nullptr, "\n");
                if (s != nullptr) {
                    if (strncmp(s, "1", 1) == 0) {
                        // 长度1Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_WRITE, LEN_HBP::HBP_LEN_1B);
                    } else if (strncmp(s, "2", 1) == 0) {
                        // 长度2Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_WRITE, LEN_HBP::HBP_LEN_2B);
                    } else if (strncmp(s, "4", 1) == 0) {
                        // 长度4Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_WRITE, LEN_HBP::HBP_LEN_4B);
                    }
                }
            } else if (strncmp(s, "a", 1) == 0) {
                // 添加硬件访问断点
                s = strtok(nullptr, "\n");
                if (s != nullptr) {
                    if (strncmp(s, "1", 1) == 0) {
                        // 长度1Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_ACCESS, LEN_HBP::HBP_LEN_1B);
                    } else if (strncmp(s, "2", 1) == 0) {
                        // 长度2Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_ACCESS, LEN_HBP::HBP_LEN_2B);
                    } else if (strncmp(s, "4", 1) == 0) {
                        // 长度4Byte
                        return AddHBP(Addr, TYPE_HBP::HBP_ACCESS, LEN_HBP::HBP_LEN_4B);
                    }
                }
            }
        }
    }

    return false;
}

bool MyDebuger::OnCmdBHC(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, "\n");
    if (s != nullptr) {
        unsigned int index = strtoul(s, nullptr, 10);
        return DelHBP(index);
    } else {
        printf("删除失败，输入格式错误\n");
    }
    return false;
}

bool MyDebuger::OnCmdG(char *buf)
{
    m_IsRun = true; // g运行
    m_CanDump = false;  // 禁用dump

    // 检查断点是否有需要恢复
    if (!m_BPReductionList.empty() || !m_MemBPPageReductionList.empty()) {
        // 设置单步
        SetSingleStep();
    }

    char *s = strtok(buf, " ");
    s = strtok(nullptr, "\n");
    if (s != nullptr) {
        void *Addr = (void *)strtoul(s, nullptr, 16);

        // 检查地址是否有效
        if (ProcessOperating::IsAddressValid(m_DebugEv.dwProcessId, Addr)) {
            // 检查这个地址是否存在断点
            if (!IsExistsBP(Addr)) {
                // 不存在设置一次性断点
                AddBP(Addr, true);
            }
        } else {
            printf("地址：%p无效", Addr);
            return false;
        }
    }

    return true;
}

bool MyDebuger::OnCmdT(char *buf)
{
    m_IsRun = false;    // 禁用g命令
    m_CanDump = false;  // 禁用dump
    // 设置单步
    SetSingleStep(true);
    return true;
}

bool MyDebuger::OnCmdP(char *buf)
{
    m_IsRun = false;    // 禁用g命令
    m_CanDump = false;  // 禁用dump

    // 读取内存中的数据
    ProcessOperating::ReadProcessMemory(m_DebugEv.dwProcessId, (PVOID)m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData));
    // 检查当前行是否是call
    if (m_MemoryData[0] == 0xe8
        || m_MemoryData[0] == 0xff
        || m_MemoryData[0] == 0x9a) {
        // 计算下一个指令位置
        m_CurrentAddr += ShowDisassembly(m_CurrentAddr, m_MemoryData, sizeof(m_MemoryData), 1, false);

        // 判断是否下过断点，没有添加临时断点
        if (!IsExistsBP((void *)m_CurrentAddr)) {
            AddBP((void *)m_CurrentAddr, true);
        }
    } else {
        // 设置单步
        SetSingleStep();
    }

    return true;
}

bool MyDebuger::OnCmdLS(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, "\n");
    if (s != nullptr) {
        // 检查是否导入成功
        if (ImportScript(s)) {
            return true;
        }
    }

    printf("导入失败\n");
    return false;
}

bool MyDebuger::OnCmdTRACE(char *buf)
{
    char *s = strtok(buf, " ");
    s = strtok(nullptr, " ");
    if (s != nullptr) {
        // 获取起始地址
        void *StartAddr = (void *)strtoul(s, nullptr, 16);
        s = strtok(nullptr, " ");
        if (s != nullptr) {
            // 获取结束地址
            void *EndAddr = (void *)strtoul(s, nullptr, 16);

            s = strtok(nullptr, "\n");

            // 设置自动跟踪
            return SetAutoTrack(StartAddr, EndAddr, s == nullptr ? "" : s);
        } else {
            printf("格式错误\n");
            return false;
        }
    } else {
        printf("格式错误\n");
        return false;
    }
}

bool MyDebuger::OnCmdDUMP(char *buf)
{
    if(!m_CanDump) {
        // 此时机不能在dump内存
        return false;
    }

    char *s = strtok(buf, " ");
    s = strtok(nullptr, " ");
    if(!s) {
        return false;
    }
    s = strtok(s, "\n");  // 获取文件名

    auto MainModuelItem = m_ModuleList.front();
    DWORD ImageBase = (DWORD)MainModuelItem.hModule;
    IMAGE_DOS_HEADER ImageDosHeader { 0 };
    IMAGE_NT_HEADERS ImageNtHeaders { 0 };

    // 读取Dos头
    ProcessOperating::ReadProcessMemory(m_pi.dwProcessId, MainModuelItem.hModule, &ImageDosHeader, sizeof(IMAGE_DOS_HEADER));

    // 读取Nt头
    ProcessOperating::ReadProcessMemory(m_pi.dwProcessId, (BYTE *)ImageBase + ImageDosHeader.e_lfanew, &ImageNtHeaders, sizeof(IMAGE_NT_HEADERS));

    // 创建文件
    HANDLE hFile = ::CreateFileA(s, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE) {
        // 创建文件失败
        return false;
    }

    // 写入Dos头
    DWORD WriteBytes = 0;
    ::WriteFile(hFile, &ImageDosHeader, sizeof(IMAGE_DOS_HEADER), &WriteBytes, NULL);

    // 写入Nt头
    ::SetFilePointer(hFile, ImageDosHeader.e_lfanew, NULL, FILE_BEGIN);
    ::WriteFile(hFile, &ImageNtHeaders, sizeof(IMAGE_NT_HEADERS), &WriteBytes, NULL);

    // 定位到节表的位置
    DWORD SectionTablePointer = ImageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ImageNtHeaders.FileHeader.SizeOfOptionalHeader;

    // 拷贝节表和节数据
    for(DWORD i = 0; i < ImageNtHeaders.FileHeader.NumberOfSections; i++, SectionTablePointer += sizeof(IMAGE_SECTION_HEADER)) {
        // 读取节表
        IMAGE_SECTION_HEADER ImageSectionHeader { 0 };
        ProcessOperating::ReadProcessMemory(m_pi.dwProcessId, (BYTE *)ImageBase + SectionTablePointer, &ImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));

        // 写入节表
        ::SetFilePointer(hFile, SectionTablePointer, NULL, FILE_BEGIN);
        ::WriteFile(hFile, &ImageSectionHeader, sizeof(IMAGE_SECTION_HEADER), &WriteBytes, NULL);

        // 判断是否是未初始化区
        if(ImageSectionHeader.SizeOfRawData == 0) {
            continue;
        }

        // 读取节数据
        BYTE *SectionData = new BYTE[ImageSectionHeader.SizeOfRawData];
        ProcessOperating::ReadProcessMemory(m_pi.dwProcessId, (BYTE *)ImageBase + ImageSectionHeader.VirtualAddress, SectionData, ImageSectionHeader.SizeOfRawData);

        // 写入节数据
        ::SetFilePointer(hFile, ImageSectionHeader.PointerToRawData, NULL, FILE_BEGIN);
        ::WriteFile(hFile, SectionData, ImageSectionHeader.SizeOfRawData, &WriteBytes, NULL);

        delete[] SectionData;
    }

    ::CloseHandle(hFile);
    return true;
}

void MyDebuger::ShowRegister()
{
    FLAGS_REGISTER Flags;
    if (ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        Flags.Flags = m_Context.EFlags;

        // 显示通用寄存器和段寄存器
        printf("EAX = %.8X  EBX = %.8X  ECX = %.8X  EDX = %.8X  EBP = %.8X  ESP = %.8X\n",
            m_Context.Eax, m_Context.Ebx, m_Context.Ecx, m_Context.Edx, m_Context.Ebp, m_Context.Esp);

        printf("ESI = %.8X  EDI = %.8X  EIP = %.8X  FS  = %.8X  GS  = %.8X  ES  = %.8X\n",
            m_Context.Esi, m_Context.Edi, m_Context.Eip, m_Context.SegFs, m_Context.SegGs, m_Context.SegEs);

        printf("DS  = %.8X  CS  = %.8X  SS  = %.8X  DR0 = %.8X  DR1 = %.8X  DR2 = %.8X\n",
            m_Context.SegDs, m_Context.SegCs, m_Context.SegSs, m_Context.Dr0, m_Context.Dr1, m_Context.Dr2);

        printf("DR3 = %.8X  DR6 = %.8X  DR7 = %.8X", m_Context.Dr3, m_Context.Dr6, m_Context.Dr7);

        // 显示标志寄存器
        printf("\t\t    ZF  PF  AF  OF  SF  DF  CF  TF  IF\r\n");
        printf("\t\t\t\t\t\t\t    %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X  %.2X\n",
            Flags.ZF, Flags.PF, Flags.AF,
            Flags.OF, Flags.SF, Flags.DF,
            Flags.CF, Flags.TF, Flags.IF);
    } else {
        printf("获取寄存器失败\n");
    }
}

void MyDebuger::ShowModule()
{
    if (m_ModuleList.empty()) {
        printf("没有加载任何模块\n");
        return;
    }
    // 遍历显示模块信息
    for (auto &item : m_ModuleList) {
        printf("名称:%20s  基址:%p  大小:%.8X  路径:%s\r\n", item.ModuleName.c_str(), item.hModule,
            item.dwModuleSize, item.ModulePath.c_str());
    }
}

void MyDebuger::ShowHelp()
{
    char help[][CHAR_MAX] = {
        "命令", " 说明",
        " u", "反汇编",
        " p", "单步步过",
        " q", "退出",
        " r", "查看寄存器",
        " t", "单步步入",
        " ls", "导入脚本",
        " es", "导出脚本",
        " dd", "查看内存数据",
        " ml", "查看脚本",
        " bpl", "查看一般断点",
        " bhl", "查看硬件断点",
        " bml", "查看内存断点",
        " bmpl", "查看分页断点",
        " g [address]", "运行",
        " bpc <number>", "删除一般断点",
        " bp <address> [sys]", "一般断点",
        " e <address> <value>", "修改内存数据",
        " bhc <address> <number>", "删除硬件断点",
        " bmc <address> <number>", "删除内存断点",
        " bm <address> <length> <r/w>", "内存断点",
        " bh <address> <e/r/a> <1/2/4>", "硬件断点",
        " trace <address> <address> <module>", "自动跟踪记录"
    };

    // 显示帮助页面
    int count = sizeof(help) / CHAR_MAX;
    for (int i = 0; i < count; i += 2) {
        printf("%-35s\t%s\n", help[i], help[i + 1]);
    }
}

void MyDebuger::QuitDebug()
{
    exit(0);
}

void MyDebuger::ShowBPList()
{
    //检查断点表是否为空
    if (!m_BPList.empty()) {
        printf("\n----------------------------断点列表-------------------------------\n");
        printf("断点数量: %d\n", m_BPList.size());
        printf("编号    地址        原始代码   修改代码  是否一次性\n");
        for (size_t i = 0; i < m_BPList.size(); i++) {
            printf("%4d    %p    %.1X         %.1X        %s\n", i, m_BPList[i].BPAddr,
                m_BPList[i].OldCode, m_BPList[i].NEwCode, (m_BPList[i].IsOnce) ? "true" : "false");
        }
        printf("-------------------------------------------------------------------\n\n");
    } else {
        printf("断点列表为空\n");
    }
}

void MyDebuger::ShowMemBPList(bool IsShowPage)
{
    //检查是否显示分页
    if (IsShowPage) {
        //检查内存断点分页表是否为空
        if (!m_MemBPPageList.empty()) {
            printf("\n--------------------------内存分页断点列表-----------------------------\n");
            printf("内存分页断点数量: %d\n", m_MemBPPageList.size());
            printf("分页编号    分页地址    分页大小    旧属性     新属性\n");

            for (size_t i = 0; i < m_MemBPPageList.size(); i++) {
                printf("%8d    %p    %.8X    %.8X   %.8X\n", i, m_MemBPPageList[i].StartAddr,
                    m_MemBPPageList[i].dwSize, m_MemBPPageList[i].dwOldProtect, m_MemBPPageList[i].dwNewProtect);
            }
            printf("-------------------------------------------------------------------\n");
        } else {
            printf("内存分页断点列表为空\n");
        }
    } else {
        //检查内存断点分页表是否为空
        if (!m_MemBPList.empty()) {
            printf("\n---------------------------内存断点列表------------------------------\n");
            printf("内存断点数量: %d\n", m_MemBPList.size());
            printf("断点编号    断点地址    断点大小    断点类型\n");

            for (size_t i = 0; i < m_MemBPList.size(); i++) {
                printf("%8d    %p    %.8X    %s\n", i, m_MemBPList[i].MemBPAddr,
                    m_MemBPList[i].dwSize, (m_MemBPList[i].MemBPType == TYPE_MEMBP::MEMBP_READ) ? "读" : "写");
            }
            printf("-------------------------------------------------------------------\n");
        } else {
            printf("内存断点列表为空\n");
        }
    }
}

void MyDebuger::ShowHBPList()
{
    //检查硬件断点链表是否为空
    if (!m_HBPList.empty()) {
        printf("\n---------------------------硬件断点列表------------------------------\n");
        printf("硬件断点数量: %d\n", m_HBPList.size());
        printf("断点序号    断点地址    断点类型    断点大小\n");

        for (size_t i = 0; i < m_HBPList.size(); i++) {
            printf("%8d    %p    ", i, m_HBPList[i].HBPAddr);

            //显示类型
            switch (m_HBPList[i].HBPType)
            {
            case TYPE_HBP::HBP_EXECUTE:
                printf("执行        ");
                break;

            case TYPE_HBP::HBP_ACCESS:
                printf("访问        ");
                break;

            case TYPE_HBP::HBP_WRITE:
                printf("写入        ");
                break;
            }

            //显示大小
            switch (m_HBPList[i].HBPLen)
            {
            case LEN_HBP::HBP_LEN_1B:
                printf("1字节\n");
                break;

            case LEN_HBP::HBP_LEN_2B:
                printf("2字节\n");
                break;

            case LEN_HBP::HBP_LEN_4B:
                printf("4字节\n");
                break;
            }
        }
        printf("-------------------------------------------------------------------\n");
    } else {
        printf("硬件断点列表为空\n");
    }
}

bool MyDebuger::SetSingleStep(bool IsEnable)
{
    FLAGS_REGISTER FlagsRegister;

    // 获取线程上下文环境
    if (ProcessOperating::GetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
        FlagsRegister.Flags = m_Context.EFlags;
        FlagsRegister.TF = IsEnable;    // 设置TF位
        m_Context.EFlags = FlagsRegister.Flags;

        // 设置线程上下文环境
        if (ProcessOperating::SetThreadContext(m_DebugEv.dwThreadId, m_Context)) {
            return true;
        }
    }
    return false;
}

bool MyDebuger::DumpTrackInfo(std::string FileName)
{
    // 创建文件
    HANDLE hFile = ::CreateFileA(FileName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    // 检查是否创建成功
    if (hFile == INVALID_HANDLE_VALUE) {
        ErrorReport::Report("CreateFileA");
        return false;
    }

    DWORD WriteBytes = 0;
    for (auto &item : m_AutoTrackList) {
        // 写入文件
        ::WriteFile(hFile, item.Data.c_str(), item.Data.length(), &WriteBytes, NULL);
    }

    // 关闭文件句柄
    ::CloseHandle(hFile);

    // 清空跟踪链表
    m_AutoTrackList.clear();
    return true;
}

bool MyDebuger::ExportScript()
{
    char FileName[MAX_PATH] { 0 };
    // 以主模块为文件名
    sprintf(FileName, "%s.scp", m_ModuleList.front().ModuleName.c_str());

    // 创建文件
    HANDLE hFile = ::CreateFileA(FileName, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    // 检查是否创建成功
    if (hFile == INVALID_HANDLE_VALUE) {
        ErrorReport::Report("CreateFileA");
        return false;
    }

    DWORD WriteBytes = 0;

    // 遍历命令链表 写入
    for (auto &item : m_CmdRecordList) {
        // 获取字符串的大小
        unsigned int StrSize = item.size();
        // 写入字符串
        ::WriteFile(hFile, item.c_str(), StrSize, &WriteBytes, NULL);
    }

    // 关闭句柄
    ::CloseHandle(hFile);
    printf("导出脚本：%s成功\n", FileName);
    return true;
}

bool MyDebuger::ImportScript(std::string FileName)
{
    // 打开文件流
    std::ifstream in(FileName);
    std::string cmd;

    // 读取行
    while(std::getline(in, cmd)) {
        m_CmdLineQueue.push(cmd);
    }

    return true;
}

bool MyDebuger::SetAutoTrack(void *StartAddr, void *EndAddr, std::string ModuleName)
{
    // 检查模块名
    if (ModuleName.empty()) {
        // 无模块名
        m_AutoTrackParam.IsQualifiedModule = false; // 不限定模块
    } else {
        // 有模块名，检查模块是否存在
        unsigned int index = 0;
        if (!IsExistsModule(ModuleName, &index)) {
            printf("模块不存在\n");
            return false;
        }
        m_AutoTrackParam.IsQualifiedModule = true; // 限定模块
        m_AutoTrackParam.ModuleStartAddr = m_ModuleList[index].hModule; // 模块起始地址
        m_AutoTrackParam.ModuleEndAddr = (void *)((DWORD64)m_ModuleList[index].hModule + m_ModuleList[index].dwModuleSize); // 模块结束地址
    }

    m_AutoTrackParam.StartAddr = StartAddr;
    m_AutoTrackParam.EndAddr = EndAddr;

    // 检查添加一次性断点
    if (AddBP(StartAddr, true) && AddBP(EndAddr, true)) {
        // 开启自动跟踪
        m_IsAutoTrack = true;
        return true;
    }

    printf("自动跟踪设置失败\n");
    return false;
}

bool MyDebuger::AppendTrackData(void *TrackAddr, std::string Data)
{
    // 检查是否限定模块
    if (m_AutoTrackParam.IsQualifiedModule) {
        // 检查地址范围是否在限定的模块内
        if (m_AutoTrackParam.ModuleStartAddr > TrackAddr || m_AutoTrackParam.ModuleEndAddr < TrackAddr) {
            return false;
        }
    }
    // 加入链表中
    if(!IsExistsTrackAddr(TrackAddr)) {
        m_AutoTrackList.push_back(AUTO_TRACK_ITEM({ TrackAddr, Data }));
    }
    return true;
}

bool MyDebuger::IsExistsTrackAddr(void *TrackAddr)
{
    for (auto &item : m_AutoTrackList) {
        if (TrackAddr == item.TrackAddr) {
            return true;    // 存在
        }
    }
    return false;
}

bool MyDebuger::IsExistsOtherBreakPoint(void *BreakPointAddr)
{
    // 检查一般断点
    for(auto &item : m_BPList) {
        if(item.BPAddr == BreakPointAddr) {
            return true;
        }
    }

    // 检查内存断点
    for(auto &item : m_MemBPPageList) {
        if(item.StartAddr <= BreakPointAddr && (DWORD64)item.StartAddr + item.dwSize >= (DWORD64)BreakPointAddr) {
            return true;
        }
    }

    // 检查硬件断点
    for(auto &item : m_HBPList) {
        if(item.HBPAddr <= BreakPointAddr && ((DWORD64)item.HBPAddr + (DWORD64)item.HBPLen + 1) >= (DWORD64)BreakPointAddr) {
            return true;
        }
    }

    return false;
}
