# MyDebuger
一个调试器的demo



## 功能

|  **命令名**  | **命令码** |  **英文说明**   | **参数1** |        **参数2**        |        **参数3**         |
| :----------: | :--------: | :-------------: | :-------: | :---------------------: | :----------------------: |
|   单步步入   |     t      |      Step       |    无     |                         |                          |
|   单步步过   |     p      |     Step Go     |    无     |                         |                          |
|     运行     |     g      |       Run       |  无/地址  |                         |                          |
| 自动跟踪记录 |   trace    |                 | 起始地址  |        结束地址         | 模块名称（NULL表示所有） |
|    反汇编    |     u      | Display Asmcode |  无/地址  |                         |                          |
| 显示内存数据 |     dd     |  Display Data   |  无/地址  |                         |                          |
|    寄存器    |     r      |    Register     |    无     |                         |                          |
| 修改内存数据 |     e      |    Edit Data    |  无/地址  |                         |                          |
|   一般断点   |     bp     |   Break Point   |   地址    |      无/sys(一次)       |                          |
| 一般断点列表 |    bpl     |     Bp List     |    无     |                         |                          |
| 删除一般断点 |    bpc     |    Clear bp     |   序号    |                         |                          |
|   硬件断点   |     bh     |     Bp Hard     |   地址    | e(执行)/w(写入)/a(访问) |     断点长度(1,2,4)      |
| 硬件断点列表 |    bhl     |  Bp Hard List   |    无     |                         |                          |
| 删除硬件断点 |    bhc     |  Clear Bp Hard  |   序号    |                         |                          |
|   内存断点   |     bm     |    Bp Memory    |   地址    |          长度           |       r(读)/w(写)        |
| 内存断点列表 |    bml     | Bp Memory List  |    无     |                         |                          |
| 分页断点列表 |    bmpl    |  Bp Page List   |    无     |                         |                          |
| 删除内存断点 |    bmc     | Clear bp Memory |   序号    |                         |                          |
|   导入脚本   |     ls     |   Load Script   |    无     |                         |                          |
|   导出脚本   |     es     |  Export Script  |    无     |                         |                          |
|   退出程序   |     q      |      Quit       |    无     |                         |                          |
|   查看模块   |     ml     |   Module List   |    无     |                         |                          |
|  Dump到文件  |    dump    |  Dump to file   |  文件名   |                         |                          |

![image](https://github.com/l0yuee/MyDebuger/blob/master/img/1.png)
