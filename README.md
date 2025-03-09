# Ghostly Hollowing Via Tampered Syscalls

## Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus?ref=gh)

[Maldev Academy Pricing](https://maldevacademy.com/pricing?ref=gh)

## Summary

This implementation utilizes two techniques covered in the recent updates to the Maldev Academy course:
  
  * [Tampered Syscalls Via Hardware BreakPoints](https://maldevacademy.com/new/modules/45?ref=gh): Used to bypass userland hooks while simultaneously spoofing the invoked syscall's arguments.
    
  * [Ghostly Hollowing](https://maldevacademy.com/new/modules/40?ref=gh): A hybrid technique between Process Hollowing and Process Ghosting.

## Tampered Syscalls

* All syscalls invoked in the implementation are called through the `TAMPER_SYSCALL` macro. This macro calls the `StoreTamperedSyscallParms` function to:
  * Determine the address of the `syscall` instruction within the `NtQuerySecurityObject` syscall stub (i.e. decoy syscall), and set a hardware breakpoint at this address.
  * Fetch the syscall number of the real invoked syscalls using the *Sorting by System Call Address* method introduced in [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2).
  * Save the invoked syscall's first four arguments.
    
* When calling the `TAMPER_SYSCALL` macro, `TAMPER_SYSCALL` will spoof the invoked syscall's first four arguments with `NULL` values. Then it'll call the `NtQuerySecurityObject` syscall, triggering the breakpoint installed earlier.

* We handle the raised exception by replacing the SSN of the decoy syscall (`NtQuerySecurityObject`) with the real invoked syscall (e.g. `ZwAllocateVirtualMemory`'s SSN). Then we replace the spoofed arguments with the real ones. These steps are executed in the `ExceptionHandlerCallbackRoutine` VEH function.


## Ghostly Hollowing

1. **Fetch the PE payload:** The implementation fetches the PE payload (`mimikatz.exe`) from the disk. In an ideal situation, you should encrypt the payload and store it in the resource section.
  
2. **Create an empty file on the disk:** Create a temporary file (`.tmp`) in the `$env:TMP` directory. This file will later be overwritten with the PE payload.

3. **Create a ghost section from the temporary file:** A ghost section is created by calling `ZwCreateSection` to create a section from the delete-pending `.tmp` file, closing the file handle, and deleting the file from the disk.

4. **Create a remote process:** Using the `CreateProcess` WinAPI, we create a remote process and map the ghost section to it.

5. **Patch the ImageBaseAddress:** Patch the `ImageBaseAddress` element of the `PEB` structure to point to the mapped ghost section, and execute the PE payload's entry point via thread hijacking.

## Demo

![DEMO1](https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls/assets/111295429/b6230f06-d341-4644-9196-f10b6da035d8)

![DEMO2](https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls/assets/111295429/ae6c9544-43f2-4a8f-82cc-2f3c9c5b7a64)

https://github.com/Maldev-Academy/GhostlyHollowingViaTamperedSyscalls/assets/111295429/ca982aac-8f78-427a-bb24-631715dd174e


## Related Maldev Academy Modules

* [New Module 40: Ghostly Hollowing](https://maldevacademy.com/new/modules/40?ref=gh)

* [New Module 45: Tampered Syscalls Via Hardware BreakPoints](https://maldevacademy.com/new/modules/45?ref=gh)

## Credits

We apologize for the oversight in not including proper attribution in this repository. While credit was given in the course, we inadvertently missed adding it here.  

All credit goes to **[@rad9800](https://github.com/rad9800/hwbp4mw)** for the original work.  

