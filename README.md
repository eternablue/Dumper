# Process Dumper

## Dumping

Dumping is usefull to get the executable in the state it is at runtime, as oposed to it being on disk. That is required to reverse a packed file for example.

## Basic idea

Before i start, if you're new to this i highly recommend you read more about the [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format). When a process is being executed it is loaded from disk into memory, and alot of things happen from there such as :

- Imports are resolved in the IAT and the required modules are loaded recursivly.
- The address of each section is replaced to the address of where the section is in the virtual address space chosen by the OS.
- The size of certain sections can be modified, for example if some allocations would occur

That poses a problem, if we simply read the data in the virtual memory and write it to a file on disk, our dump will be invalid because the IAT would be broken, and would only be valid in the context of runtime, not storage. If you would to open it in IDA you would be greeted with an error message.

To fix that we need to copy each section seperatly to our buffer and change the data acordingly in the IAT. For example we have to replace the absolute address of each section (in virtual memory) to a relative address to the beggining of the file. That is done like so :
```cpp
for (uint64_t i = 0; i < image_nt_header->FileHeader.NumberOfSections; ++i, ++section)
{
  section->PointerToRawData = section->VirtualAddress;
  section->SizeOfRawData = section->Misc.VirtualSize;
}
```

Once that's done we can simply write our buffer that contains the fixed PE Header and the sections to a file on disk. If we open that on IDA we now get a valid executable to analyze.

## Showcase
![image](.gif)
