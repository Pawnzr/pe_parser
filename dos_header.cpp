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
  IMAGE_DOS_HEADER dosHeader;
  file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
    std::cerr << "File không phải là file PE hợp lệ!" << std::endl;
    file.close();
    return 1;
  }

  // In giá trị của một số trường trong DOS Header
    std::cout << "e_magic: " << std::hex << dosHeader.e_magic << std::endl;
    std::cout << "e_lfanew: " << std::hex << dosHeader.e_lfanew << std::endl;

}