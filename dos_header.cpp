#include <iostream>
#include <fstream>
#include <winnt.h>

int main() {
  // Mở file notepad.exe ở chế độ nhị phân
    std::ifstream file("C:\\Windows\\System32\\notepad.exe", std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Không thể mở file notepad.exe!" << std::endl;
        return 1;
    }

    // paring DOS Header
    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "File không phải là file PE hợp lệ!" << std::endl;
        file.close();
        return 1;
    }

    std::cout << "e_magic: " << std::hex << dosHeader.e_magic << std::endl;
    std::cout << "e_lfanew: " << std::hex << dosHeader.e_lfanew << std::endl;
    
    // parsing NT header
    DWORD ntHeaderOffset = dosHeader.e_lfanew;
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
    std::cout << "Signature: " << std::hex << ntHeaders.Signature << std::endl;
    std::cout << "Machine: " << std::hex << ntHeaders.FileHeader.Machine << std::endl;
    std::cout << "NumberOfSections: " << std::dec << ntHeaders.FileHeader.NumberOfSections << std::endl;
    
    IMAGE_OPTIONAL_HEADER& optionalHeader = ntHeaders.OptionalHeader;
    // if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && 
    //     optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    //     std::cerr << "Optional Header không hợp lệ!" << std::endl;
    //     file.close();
    //     return 1;
    // }
    
    printf("\n******* FILE HEADER *******\n");
    printf("\tMachine: 0x%x\n", ntHeaders.FileHeader.Machine);
    printf("\tNumberOfSections: %d\n", ntHeaders.FileHeader.NumberOfSections);
    printf("\tTimeDateStamp: %d\n", ntHeaders.FileHeader.TimeDateStamp);
    printf("\tPointerToSymbolTable: 0x%x\n", ntHeaders.FileHeader.PointerToSymbolTable);
    printf("\tNumberOfSymbols: 0x%x\n", ntHeaders.FileHeader.NumberOfSymbols);
    printf("\tSizeOfOptionalHeader: 0x%x\n", ntHeaders.FileHeader.SizeOfOptionalHeader);
    printf("\tCharacteristics: 0x%x\n", ntHeaders.FileHeader.Characteristics);
    printf("\n******* DATA DIRECTORIES *******\n");
    printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", ntHeaders.OptionalHeader.DataDirectory[0].VirtualAddress, ntHeaders.OptionalHeader.DataDirectory[0].Size);
    printf("\tExport Directory Address: 0x%x; Size: 0x%x\n", ntHeaders.OptionalHeader.DataDirectory[1].VirtualAddress, ntHeaders.OptionalHeader.DataDirectory[1].Size);

	printf("\n******* OPTIONAL HEADER *******\n");
    std::cout << "\tIMAGE_NT_OPTIONAL_HDR32_MAGIC: " << std::hex << IMAGE_NT_OPTIONAL_HDR_MAGIC << std::endl;
    std::cout << "\tIMAGE_NT_OPTIONAL_HDR32_MAGIC: " << std::hex << IMAGE_NT_OPTIONAL_HDR64_MAGIC << std::endl;
    std::cout << "\tMagic Number: " << std::hex << optionalHeader.Magic << std::endl;
    std::cout << "\tAddressOfEntryPoint: " << std::hex << optionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "\tImageBase: " << std::hex << optionalHeader.ImageBase << std::endl;
    std::cout << "\tSizeOfImage: " << std::dec << optionalHeader.SizeOfImage << std::endl;
    file.close();
    return 0;

}