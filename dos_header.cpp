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
    
    
    
    file.close();
    return 0;

}