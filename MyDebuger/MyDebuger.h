#pragma once
#include <string>
#include <vector>
#include <queue>
#include <Windows.h>
#include<Zycore/Format.h>
#include<Zycore/LibC.h>
#include<Zydis/Zydis.h>
#include "DebugDS.h"

class MyDebuger
{
public:
    MyDebuger(std::string strApp);
    virtual ~MyDebuger();



    // 调试器开始工作
    void Work();


protected:
    // 处理异常调试事件
    DWORD OnDebugExceptionEvent();

    // 处理创建线程事件
    DWORD OnCreateThreadEvent();

    // 处理创建进程事件
    DWORD OnCreateProcessEvent();

    // 处理退出线程事件
    DWORD OnExitThreadEvent();

    // 处理退出进程事件
    DWORD OnExitProcessEvent();

    // 处理加载DLL事件
    DWORD OnLoadDllEvent();

    // 处理卸载DLL事件
    DWORD OnUnloadDLLEvent();

    // 处理断点异常
    DWORD OnExceptionBreakPoint();

    // 处理内存访问异常
    DWORD OnExceptionAccessViolation();

    // 处理单步异常
    DWORD OnExceptionSingleStep();

    // 处理硬件断点异常
    DWORD OnExceptionHardwareBreakPoint();

    // 获取用户命令行
    DWORD GetCmdLine();

    /*
     * 添加断点
     *      BPAddr：断点地址
     *      IsOnecBP：是否是一次性断点
     */
    bool AddBP(void *BPAddr, bool IsOnecBP = false);

    /*
     * 删除断点
     *      number：断点的编号
     */
    bool DelBP(unsigned int number);

    /*
     * 断点是否存在
     *      BPAddr：断点地址
     */
    bool IsExistsBP(void *BPAddr);

    /*
     * 添加内存断点
     *      BPAddr：断点地址
     *      BPSize：大小
     *      BPType：断点类型
     */
    bool AddMemBP(void *BPAddr, unsigned int BPSize, TYPE_MEMBP BPType);

    /*
     * 检查内存分页是否存在
     *      PageAddr：分页地址
     *      Index：索引
     */
    bool IsExistsMemPage(void *PageAddr, unsigned int *Index = nullptr);

    /*
     * 是否存在内存断点
     *      PageAddr：分页地址
     *      Index：索引
     */
    bool IsExistMemBP(void *PageAddr, unsigned int *Index = nullptr);


    /*
     * 删除内存断点
     *      number：断点的编号
     */
    bool DelMemBP(unsigned int number);

    /*
     * 添加硬件断点
     *      BPAddr：断点地址
     *      HBPType：断点类型
     *      HBPSize：断点大小
     */
    bool AddHBP(void *BPAddr, TYPE_HBP HBPType, LEN_HBP HBPSize);

    /*
     * 删除硬件断点
     *      number：断点的编号
     */
    bool DelHBP(unsigned int number);

    /*
     * 添加模块到链表中
     *      hFile：模块的文件句柄
     *      IsLoadDLl：是否是加载DLL
     */
    void AppendModule(HANDLE hFile, bool IsLoadDLl = false);

    /*
     * 检查模块是否存在
     *      ModuleName：模块名
     *      Index：索引
     */
    bool IsExistsModule(std::string ModuleName, unsigned int *Index);


    /*
     * 反汇编并显示
     *      runtime_address   运行时地址显示地址
     *      data              数据缓冲区
     *      length            数据大小
     *      dwLine            显示几行
     *      bIsShow           是否显示默认显示(如果不显示可以用来计算反汇编地址位置)
     */
    ZyanUSize ShowDisassembly(ZyanU64 runtime_address, ZyanU8* data, ZyanUSize length, DWORD dwLine, bool bIsShow = true);


    /*
     * 显示十六进制
     *      dwAddress         显示地址
     *      pBuf              数据缓冲区
     *      dwSize            数据大小
     *      dwLine            显示几行
    */
    ZyanUSize ShowHex(ZyanU64 ZuAddress, PBYTE pBuf, DWORD dwSize, DWORD dwLine);


    /*
     * 处理u命令，u [address]
     *      buf：命令缓冲区
     */
    bool OnCmdU(char *buf);

    /*
     * 处理dd命令，dd [address]
     *      buf：命令缓冲区
     */
    bool OnCmdDD(char *buf);

    /*
     * 处理e命令，e <address> <value>
     *      buf：命令缓冲区
     */
    bool OnCmdE(char *buf);

    /*
     * 处理bp命令，bp <address> [sys]
     *      buf：命令缓冲区
     */
    bool OnCmdBP(char *buf);

    /*
     * 处理bpc命令，bpc <number>
     *      buf：命令缓冲区
     */
    bool OnCmdBPC(char *buf);

    /*
     * 处理bmc命令，bmc <number>
     *      buf：命令缓冲区
     */
    bool OnCmdBMC(char *buf);

    /*
     * 处理bm命令，bm <address> <length> <type>
     *      buf：命令缓冲区
     */
    bool OnCmdBM(char *buf);

    /*
     * 处理bh命令，bh <address> <type> <length> 
     *      buf：命令缓冲区
     */
    bool OnCmdBH(char *buf);

    /*
     * 处理bhc命令，bhc <number>
     *      buf：命令缓冲区
     */
    bool OnCmdBHC(char *buf);


    /*
     * 处理g命令，g [address]
     *      buf：命令缓冲区
     */
    bool OnCmdG(char *buf);

    /*
     * 处理t命令，t
     *      buf：命令缓冲区
     */
    bool OnCmdT(char *buf);

    /*
     * 处理p命令，p
     *      buf：命令缓冲区
     */
    bool OnCmdP(char *buf);

    /*
     * 处理ls命令，ls <file>
     *      buf：命令缓冲区
     */
    bool OnCmdLS(char *buf);

    /*
     * 处理trace命令，trace <address> <address> [module]
     *      buf：命令缓冲区
     */
    bool OnCmdTRACE(char *buf);

    /*
     * 处理dump命令，dump <file name>
     *      buf：命令缓冲区
     */
    bool OnCmdDUMP(char *buf);

    // 显示寄存器
    void ShowRegister();

    // 显示模块
    void ShowModule();

    // 查看帮助
    void ShowHelp();

    // 退出
    void QuitDebug();

    // 显示断点列表
    void ShowBPList();

    /*
     * 显示内存断点列表
     *      IsShowPage：是否显示分页
     */
    void ShowMemBPList(bool IsShowPage = false);

    // 显示硬件断点列表
    void ShowHBPList();

    /*
     * 设置单步
     *      IsEnable：是否开启单步
     */
    bool SetSingleStep(bool IsEnable = true);

    /*
     * dump跟踪信息
     *      FileName：文件名
     */
    bool DumpTrackInfo(std::string FileName);

    // 导出脚本
    bool ExportScript();

    /*
     * 导入脚本
     *      FileName：文件名
     */
    bool ImportScript(std::string FileName);

    /*
     * 设置自动跟踪参数
     *      StartAddr：起始地址
     *      EndAddr：结束地址
     *      ModuleName：模块名
     */
    bool SetAutoTrack(void *StartAddr, void *EndAddr, std::string ModuleName = "");

    /*
     * 增加跟踪节点数据
     *      TrackAddr：地址
     *      Data：数据
     */
    bool AppendTrackData(void *TrackAddr, std::string Data);

    /*
     * 跟踪的地址是否重复
     *      TrackAddr：地址
     */
    bool IsExistsTrackAddr(void *TrackAddr);

    /*
     * 是否存在其他断点
     *      BreakPointAddr：断点地址
     */
    bool IsExistsOtherBreakPoint(void *BreakPointAddr);

private:
    // 反汇编引擎zydis相关
    ZydisDecoder m_Decoder;
    ZyanU8 m_MemoryData[0x1000];    // 存放代码的缓冲区
    ZyanU64 m_CurrentAddr = 0;  // 当前异常的地址


    // 调试器相关
    bool m_IsStart = false;   // 是否可以启动
    DEBUG_EVENT m_DebugEv;    // 调试事件
    DWORD m_dwContinueStatus = DBG_CONTINUE;    // 调试处理状态
    bool m_IsSysBP = true;  // 是否是系统断点
    CONTEXT m_Context;      // 线程上下文环境
    bool m_IsAutoTrack = false;   // 是否自动追踪
    bool m_IsTrack = false; // 是否开启跟踪
    bool m_IsRun = false;   // g命令运行
    bool m_CanDump = true;  // 是否可以dump文件

    std::vector<AUTO_TRACK_ITEM> m_AutoTrackList;   // 自动跟踪链表
    AUTO_TRACK_PARAM m_AutoTrackParam;  // 自动跟踪参数

    std::vector<MODULE_ITEM> m_ModuleList;  // 模块链表
    std::vector<THREAD_ITEM> m_ThreadList;  // 线程链表

    std::vector<BP_ITEM> m_BPList;          // 断点链表
    std::vector<BP_ITEM> m_BPReductionList; // 断点还原链表
    std::vector<MEMBP_ITEM> m_MemBPList;                    // 内存断点链表
    std::vector<MEM_PAGE_ITEM> m_MemBPPageList;           // 内存分页断点链表
    std::vector<MEM_PAGE_ITEM> m_MemBPPageReductionList;  // 内存分页断点还原链表
    std::vector<HBP_ITEM> m_HBPList;            // 硬件断点链表
    std::vector<HBP_ITEM> m_HBPReductionList;   // 硬件断点还原链表

    std::queue<std::string> m_CmdLineQueue;     // 命令队列
    std::vector<std::string> m_CmdRecordList;   // 命令记录链表

    // 被调试进程相关
    std::string m_strApp;   // 被调试程序
    STARTUPINFO m_si { 0 };
    PROCESS_INFORMATION m_pi { 0 };
};

