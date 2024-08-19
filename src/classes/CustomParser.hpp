#ifndef CUSTOM_PARSER_HPP
#define CUSTOM_PARSER_HPP

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <cstdint>

// This is a simple parser for PE files for Header manipulation
#pragma pack(push, 1)

struct DOSHeader {
    uint16_t e_magic; // Magic number: 0x5A4D
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
    uint32_t Signature; // PE\0\0
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct OptionalHeader {
    uint16_t Magic; // 0x10B - PE32, 0x20B - PE32+
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint64_t ImageBase;
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
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
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

class CustomParser {
public:
    CustomParser(const std::string& file_path);

    void parse();

    void write(const std::string& output_file_path);

    void print();

    DOSHeader* getDOSHeader();

    PEHeader* getPEHeader();

    OptionalHeader* getOptionalHeader();

    std::vector<SectionHeader>& getSectionHeaders();

    std::vector<uint8_t>& getFileContents();


private:
    std::string file_path;
    std::ifstream file;
    DOSHeader dos_header;
    PEHeader pe_header;
    OptionalHeader optional_header;
    std::vector<SectionHeader> sections;
    std::vector<uint8_t> fileContents; // Store the entire file contents
};

#endif // CUSTOM_PARSER
