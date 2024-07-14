#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <cstdint>  // Include this header for fixed-width integer types

#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct PEHeader {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct OptionalHeader {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

struct SectionHeader {
    uint8_t Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// set console color constants
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"



void addOverlay(const char* filePath, size_t overlaySize) {
    std::ofstream outFile(filePath, std::ios::out | std::ios::binary | std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "Could not open file for adding overlay!" << std::endl;
        return;
    }

    // byte \x42
    std::vector<char> buffer(overlaySize, 0x42);
    outFile.write(buffer.data(), buffer.size());
    outFile.close();

    std::cout << GREEN << "Overlay added successfully!" << RESET << std::endl;
}

void updateSectionHeaders(const char* filePath, float rawSizePercentage = 0.8) {
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Could not open file!" << std::endl;
        return;
    }

    DOSHeader dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(DOSHeader));

    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    PEHeader peHeader;
    file.read(reinterpret_cast<char*>(&peHeader), sizeof(PEHeader));

    OptionalHeader optionalHeader;
    file.read(reinterpret_cast<char*>(&optionalHeader), sizeof(OptionalHeader));

    int numberOfSections = peHeader.NumberOfSections;
    int sectionHeadersOffset = dosHeader.e_lfanew + sizeof(PEHeader) + peHeader.SizeOfOptionalHeader;

    std::vector<SectionHeader> sectionHeaders(numberOfSections);
    file.seekg(sectionHeadersOffset, std::ios::beg);
    file.read(reinterpret_cast<char*>(sectionHeaders.data()), sizeof(SectionHeader) * numberOfSections);

    file.close();
    bool updated = false;
    /*int sum_raw_size = 0;
    for (auto& section : sectionHeaders) {
        sum_raw_size += section.SizeOfRawData;
    }*/
    size_t sum_raw_size = 0;
    //std::cout << GREEN << "[+] Sum of raw sizes: " << sum_raw_size << " ; 0x" << std::hex << sum_raw_size << RESET << std::endl;
    for (auto& section : sectionHeaders) {
        //std::cout << "Section " << section.Name << " raw size: " << section.SizeOfRawData << std::endl;
        // if raw size of section is 0, set it to 80% of the maximum raw size allowed
        if (section.SizeOfRawData <= 0) {
            // convert to uint32_t  and give value : sum_raw_size * rawSizePercentage
            section.SizeOfRawData = static_cast<uint32_t>(section.Misc.VirtualSize + (section.Misc.VirtualSize * rawSizePercentage));
            sum_raw_size += section.SizeOfRawData;
            // print in hex
            std::cout << "[+] Section " << section.Name << " raw size updated to " << "(" << section.SizeOfRawData << ")" <<  std::endl;
            std::cout << "[+] Section " << section.Name << " raw size updated to 0x" << std::hex << section.SizeOfRawData <<  std::endl;
            updated = true;
        }
    }

    std::ofstream outFile(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Could not open file for writing!" << std::endl;
        return;
    }

    
    if (updated)
    {
        outFile.seekp(sectionHeadersOffset, std::ios::beg);
        outFile.write(reinterpret_cast<char*>(sectionHeaders.data()), sizeof(SectionHeader) * numberOfSections);
        std::cout << GREEN << "Section headers updated successfully!" << RESET << std::endl;
    }else{
        std::cout << RED << "No change." << RESET << std::endl;
    }
    outFile.close();

    // add overlay
    addOverlay(filePath, sum_raw_size);
    
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        // description
        std::cerr << "This program updates the raw size of PE file sections (those having a zero section size) to a specified percentage of the maximum allowed to it functional." << std::endl;
        // usage
        std::cerr << "Usage: " << argv[0] << " <input PE file path> [--size <raw size percentage as a float 0.1-0.9>]" << std::endl;
        return 1;
    }

    const char* inputFilePath = argv[1];
    float rawSizePercentage = 0.2; // Default value

    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            rawSizePercentage = std::strtof(argv[++i], nullptr);
        }
    }

    updateSectionHeaders(inputFilePath, rawSizePercentage);

    return 0;
}
