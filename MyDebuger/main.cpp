#include <windows.h>
#include <iostream>
#include "MyDebuger.h"


int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cout << "Usage: MyDebug.exe < target file >" << std::endl;
        return 0;
    }

    std::string file_name = argv[1];
    MyDebuger debuger(file_name);
    debuger.Work();

    return 0;
}
