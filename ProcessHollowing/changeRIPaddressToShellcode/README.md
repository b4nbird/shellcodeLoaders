1. 创建挂起进程（使用 `CREATE_SUSPENDED`标志调用 `CreateProcess` API）；或者使用 SuspendThread 函数挂起目标线程
2. VirtualAllocEx函数申请一个可读、可写、可执行的内存。
3. 调用WriteProcessMemory将Shellcode数据写入刚申请的内存中。
4. 调用GetThreadContext，设置获取标志为CONTEXT_FULL，即获取新进程中所有线程的上下文。
5. 修改线程上下文中EIP/RIP的值为申请的内存的首地址，通过SetThreadContext函数设置回主线程中。
6. 调用ResumeThread恢复主线程。