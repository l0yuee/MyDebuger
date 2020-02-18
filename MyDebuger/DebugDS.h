#pragma once

#include <Windows.h>
#include <string>

// 标志寄存器
union FLAGS_REGISTER {
    unsigned int Flags;
    struct {
        unsigned int CF : 1;
        unsigned int : 1;
        unsigned int PF : 1;
        unsigned int : 1;
        unsigned int AF : 1;
        unsigned int : 1;
        unsigned int ZF : 1;
        unsigned int SF : 1;
        unsigned int TF : 1;
        unsigned int IF : 1;
        unsigned int DF : 1;
        unsigned int OF : 1;
    };
};

// 硬件DR7寄存器
union DR7 {
    // 设置全局 L0-L3
    // 断点长度 LEN0-LEN3    00：1字节       01：2字节      11：4字节
    // 断点类型 RW0-RW3      00：执行        01：写入       11：读写
    struct {
        unsigned int L0 : 1;
        unsigned int G0 : 1;
        unsigned int L1 : 1;
        unsigned int G1 : 1;
        unsigned int L2 : 1;
        unsigned int G2 : 1;
        unsigned int L3 : 1;
        unsigned int G3 : 1;
        unsigned int LE : 1;
        unsigned int GE : 1;
        unsigned int : 3;
        unsigned int GD : 1;
        unsigned int : 2;

        unsigned int RW0 : 2;
        unsigned int LEN0 : 2;

        unsigned int RW1 : 2;
        unsigned int LEN1 : 2;

        unsigned int RW2 : 2;
        unsigned int LEN2 : 2;

        unsigned int RW3 : 2;
        unsigned int LEN3 : 2;

    };
    unsigned int Dr7;
};


// 模块节点
struct MODULE_ITEM {
    HANDLE hModule;             // 模块句柄
    DWORD dwModuleSize;         // 模块大小
    std::string ModuleName;     // 模块名字
    std::string ModulePath;     // 模块路径
};

// 线程节点
struct THREAD_ITEM {
    HANDLE hThread;                         // 线程句柄
    void *ThreadLocalBase;                  // 数据块指针
    LPTHREAD_START_ROUTINE StartAddress;    // 回调地址
};

// 断点节点
struct BP_ITEM {
    void *BPAddr;       // 断点地址
    BYTE OldCode;       // 原始代码
    BYTE NEwCode;       // 新代码
    bool IsOnce;        // 是否一次性
};

// 内存断点的类型
enum TYPE_MEMBP {
    MEMBP_READ,   // 读
    MEMBP_WRITE   // 写
};

// 内存断点节点
struct MEMBP_ITEM {
    void *MemBPAddr;        // 内存断点地址
    DWORD dwSize;          // 大小
    TYPE_MEMBP MemBPType;   // 内存断点类型
};

// 内存分页节点
struct MEM_PAGE_ITEM {
    void *StartAddr;        // 起始地址
    DWORD dwSize;           // 大小
    DWORD dwOldProtect;     // 原先保护属性
    DWORD dwNewProtect;     // 新的保护属性
};

// 硬件断点的类型
enum TYPE_HBP {
    HBP_EXECUTE = 0,    // 执行
    HBP_WRITE = 1,      // 写
    HBP_ACCESS = 3      // 访问
};

// 硬件断点的地址长度
enum LEN_HBP {
    HBP_LEN_1B = 0,     // 1字节
    HBP_LEN_2B = 1,     // 2字节
    HBP_LEN_4B = 3      // 4字节
};

// 硬件断点节点
struct HBP_ITEM {
    DWORD DrId;         // 断点寄存器的编号Dr0-Dr3
    void *HBPAddr;      // 断点地址
    TYPE_HBP HBPType;   // 硬件断点类型
    LEN_HBP HBPLen;     // 硬件断点长度
};

// 自动跟踪参数
struct AUTO_TRACK_PARAM {
    void *StartAddr;            // 开始地址
    void *EndAddr;              // 结束地址
    bool IsQualifiedModule;     // 是否限定模块
    void *ModuleStartAddr;      // 模块开始地址
    void *ModuleEndAddr;        // 模块结束地址
};

// 自动跟踪节点
struct AUTO_TRACK_ITEM {
    void *TrackAddr;    // 地址
    std::string Data;   // 记录
};