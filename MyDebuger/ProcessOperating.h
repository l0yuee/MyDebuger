#pragma once

#include <Windows.h>

/*
 * 进程操作类
 * 负责同进程相关的操作
 * 包括：
 *      1. 读写内存
 *      2. 获取设置线程上下文环境
 *      3. 查询修改内存属性
 *      4. 检查地址是否有效
 */

class ProcessOperating
{
public:
    ProcessOperating();
    virtual ~ProcessOperating();

    /*
     * 创建进程
     *      strApp：进程名
     *      dwCreateFlags：创建标志
     *      si：启动信息
     *      pi：进程信息
     */
    static bool CreateProcess(char *strApp, DWORD dwCreateFlags, STARTUPINFOA &si, PROCESS_INFORMATION &pi)
    {
        return ::CreateProcess(NULL, strApp, NULL, NULL, FALSE, dwCreateFlags, NULL, NULL, &si, &pi) != 0;
    }

    /*
     * 读内存
     *      dwProcessPid: 进程id
     *      lpBaseAddress：基地址
     *      lpBuffer: 缓冲区
     *      dwSize：读取字节数
     */
    static bool ReadProcessMemory(DWORD dwProcessPid, PVOID lpBaseAddress, PVOID lpBuffer, DWORD dwSize)
    {
        bool ret = false;
        // 打开进程获取进程句柄
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessPid);

        if(hProcess && ::ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, dwSize, NULL)) {  // 句柄有效且读取成功
            ::CloseHandle(hProcess);
            ret = true;
        } else {
            hProcess == NULL ? 1 : ::CloseHandle(hProcess); // 若句柄有效且操作失败，关闭句柄
        }

        return ret;
    }

    /*
     * 写内存
     *      dwProcessPid: 进程id
     *      lpBaseAddress：基地址
     *      lpBuffer: 缓冲区
     *      dwSize：读取字节数
     */
    static bool WriteProcessMemory(DWORD dwProcessPid, PVOID lpBaseAddress, PVOID lpBuffer, DWORD dwSize)
    {
        bool ret = false;
        // 打开进程获取进程句柄
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessPid);

        if (hProcess && ::WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, dwSize, NULL)) {  // 句柄有效且写入成功
            ::CloseHandle(hProcess);
            ret = true;
        } else {
            hProcess == NULL ? 1 : ::CloseHandle(hProcess); // 若句柄有效且操作失败，关闭句柄
        }

        return ret;
    }

    /*
     * 获取线程上下文环境
     *      dwProcessTid：线程id
     *      lpContext：线程上下文环境
     */
    static bool GetThreadContext(DWORD dwProcessTid, CONTEXT &lpContext)
    {
        bool ret = false;
        // 打开线程获取线程句柄
        HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwProcessTid);

        if(hThread) {   // 句柄有效，获取线程上下文环境
            lpContext.ContextFlags = CONTEXT_ALL;
            if(::GetThreadContext(hThread, &lpContext)) {
                ret = true;
            }
            ::CloseHandle(hThread);
        }
        return ret;
    }

    /*
     * 设置线程上下文环境
     *      dwProcessTid：线程id
     *      lpContext：线程上下文环境
     */
    static bool SetThreadContext(DWORD dwProcessTid, CONTEXT &lpContext)
    {
        bool ret = false;
        // 打开线程获取线程句柄
        HANDLE hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, dwProcessTid);

        if (hThread) {   // 句柄有效，设置线程上下文环境
            lpContext.ContextFlags = CONTEXT_ALL;
            if (::SetThreadContext(hThread, &lpContext)) {
                ret = true;
            }
            ::CloseHandle(hThread);
        }
        return ret;
    }

    /*
     * 查询内存属性
     *      dwProcessPid：进程id
     *      lpBaseAddress：基地址
     *      mbi：内存信息
     */
    static bool VirtualQueryEx(DWORD dwProcessPid, PVOID lpBaseAddress, MEMORY_BASIC_INFORMATION &mbi)
    {
        bool ret = false;
        // 打开进程获取进程句柄
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessPid);

        if (hProcess && ::VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {  // 句柄有效且查询成功
            ::CloseHandle(hProcess);
            ret = true;
        } else {
            hProcess == NULL ? 1 : ::CloseHandle(hProcess); // 若句柄有效且操作失败，关闭句柄
        }

        return ret;
    }

    /*
     * 修改内存属性
     *      dwProcessPid：进程id
     *      lpBaseAddress：基地址
     *      mbi：内存信息
     */
    static bool VirtualProtectEx(DWORD dwProcessPid, PVOID pAddress, DWORD dwSize, DWORD flNewProtect)
    {
        bool ret = false;
        // 打开进程获取进程句柄
        HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessPid);
        DWORD flOldProtect; // 原先属性

        if (hProcess && ::VirtualProtectEx(hProcess, pAddress, dwSize, flNewProtect, &flOldProtect)) {  // 句柄有效且修改成功
            ::CloseHandle(hProcess);
            ret = true;
        } else {
            hProcess == NULL ? 1 : ::CloseHandle(hProcess); // 若句柄有效且操作失败，关闭句柄
        }

        return ret;
    }

    /*
     * 检查内存地址是否有效
     *      dwProcessPid：进程id
     *      lpBaseAddress：基地址
     */
    static bool IsAddressValid(DWORD dwProcessPid, PVOID lpBaseAddress)
    {
        MEMORY_BASIC_INFORMATION mbi;
        // 查询内存属性
        VirtualQueryEx(dwProcessPid, lpBaseAddress, mbi);
        return mbi.Protect != PAGE_NOACCESS;
    }
};

