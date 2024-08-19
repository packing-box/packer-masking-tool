#include "CustomParser.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <cstdint>



CustomParser::CustomParser(const std::string& file_path) : file_path(file_path) {
    
}

void CustomParser::parse() {
    file.open(file_path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file");
    }
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(&dos_header), sizeof(DOSHeader));
    if(dos_header.e_magic != 0x5A4D) {
        throw std::runtime_error("Invalid DOS header magic number");
    }
    file.seekg(dos_header.e_lfanew, std::ios::beg);
    file.read(reinterpret_cast<char*>(&pe_header), sizeof(PEHeader));
    if(pe_header.Signature != 0x4550) {
        throw std::runtime_error("Invalid PE header magic number");
    }
    file.read(reinterpret_cast<char*>(&optional_header), sizeof(OptionalHeader));
    size_t sectionHeadersOffset = dos_header.e_lfanew + sizeof(PEHeader) + pe_header.SizeOfOptionalHeader;

    sections.resize(pe_header.NumberOfSections);
    file.seekg(sectionHeadersOffset, std::ios::beg);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(SectionHeader) * pe_header.NumberOfSections);

    // Read the entire file contents
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    fileContents.resize(fileSize);
    file.read(reinterpret_cast<char*>(fileContents.data()), fileSize);

    file.close();
}

void CustomParser::write(const std::string& output_file_path) {
    std::ofstream output_file(output_file_path, std::ios::binary);
    if (!output_file.is_open()) {
        throw std::runtime_error("Failed to open output file");
    }

    // Copy the entire original file
    output_file.write(reinterpret_cast<char*>(fileContents.data()), fileContents.size());

    // Modify DOS header
    output_file.seekp(0, std::ios::beg);
    output_file.write(reinterpret_cast<char*>(&dos_header), sizeof(DOSHeader));

    // Modify PE header
    output_file.seekp(dos_header.e_lfanew, std::ios::beg);
    output_file.write(reinterpret_cast<char*>(&pe_header), sizeof(PEHeader));
    
    // Modify Optional header
    output_file.write(reinterpret_cast<char*>(&optional_header), sizeof(OptionalHeader));

    // Modify Section headers
    size_t sectionHeadersOffset = dos_header.e_lfanew + sizeof(PEHeader) + pe_header.SizeOfOptionalHeader;
    output_file.seekp(sectionHeadersOffset, std::ios::beg);
    output_file.write(reinterpret_cast<char*>(sections.data()), sizeof(SectionHeader) * sections.size());

    output_file.close();
}

void CustomParser::print() {
    std::cout << "DOS Header:" << std::endl;
    std::cout << "e_magic: " << std::hex << dos_header.e_magic << std::endl;
    std::cout << "e_lfanew: " << std::hex << dos_header.e_lfanew << std::endl;

    std::cout << "PE Header:" << std::endl;
    std::cout << "Signature: " << std::hex << pe_header.Signature << std::endl;
    std::cout << "Machine: " << std::hex << pe_header.Machine << std::endl;
    std::cout << "NumberOfSections: " << std::hex << pe_header.NumberOfSections << std::endl;
    std::cout << "SizeOfOptionalHeader: " << std::hex << pe_header.SizeOfOptionalHeader << std::endl;
    std::cout << "Characteristics: " << std::hex << pe_header.Characteristics << std::endl;

    std::cout << "Optional Header:" << std::endl;
    std::cout << "Magic: " << std::hex << optional_header.Magic << std::endl;
    std::cout << "AddressOfEntryPoint: " << std::hex << optional_header.AddressOfEntryPoint << std::endl;
    std::cout << "ImageBase: " << std::hex << optional_header.ImageBase << std::endl;
    std::cout << "Section Alignment: " << std::hex << optional_header.SectionAlignment << std::endl;
    std::cout << "File Alignment: " << std::hex << optional_header.FileAlignment << std::endl;
    std::cout << "SizeOfImage: " << std::hex << optional_header.SizeOfImage << std::endl;
    std::cout << "SizeOfHeaders: " << std::hex << optional_header.SizeOfHeaders << std::endl;

    std::cout << "Sections:" << std::endl;
    for (size_t i = 0; i < sections.size(); i++) {
        std::cout << "Name: " << sections[i].Name << std::endl;
        std::cout << "VirtualSize: " << std::hex << sections[i].Misc.VirtualSize << std::endl;
        std::cout << "VirtualAddress: " << std::hex << sections[i].VirtualAddress << std::endl;
        std::cout << "SizeOfRawData: " << std::hex << sections[i].SizeOfRawData << std::endl;
        std::cout << "PointerToRawData: " << std::hex << sections[i].PointerToRawData << std::endl;
        std::cout << "Characteristics: " << std::hex << sections[i].Characteristics << std::endl;
        std::cout << std::endl;
    }
}

DOSHeader* CustomParser::getDOSHeader() {
    return &dos_header;
}

PEHeader* CustomParser::getPEHeader() {
    return &pe_header;
}

OptionalHeader* CustomParser::getOptionalHeader() {
    return &optional_header;
}

std::vector<SectionHeader>& CustomParser::getSectionHeaders() {
    return sections;
}

std::vector<uint8_t>& CustomParser::getFileContents() {
    return fileContents;
}