#include "RawSizeEditor.hpp"
#include "constants.hpp"


RawSizeEditor::RawSizeEditor(const char* filePath) : filePath(filePath) {}

void RawSizeEditor::addOverlay(size_t overlaySize) {
    if (overlaySize == 0) {
        std::cout << RED << "[!] No overlay to add (0)." << RESET << std::endl;
        return;
    }
    std::ofstream outFile(filePath, std::ios::out | std::ios::binary | std::ios::app);
    if (!outFile.is_open()) {
        std::cerr << "[!] Could not open file for adding overlay!" << RESET << std::endl;
        return;
    }

    // TODO: Make random and random number byte \x42
    std::vector<char> buffer(overlaySize, 0x42);
    outFile.write(buffer.data(), buffer.size());
    outFile.close();

    std::cout << GREEN << "[+] (0x" << overlaySize << ") Overlay added successfully!" << RESET << std::endl;
}

size_t RawSizeEditor::edit(float rawSizePercentage, bool modeMaxFileSize, bool modeAllSections) {
    if (rawSizePercentage < 0.0 || rawSizePercentage > 1.0) {
        std::cerr << RED << "[!] Invalid raw size percentage value! (0.0-1.0)"  << RESET<< std::endl;
        return 0;
    }

    size_t sum_added_raw_size = updateSectionHeaders(rawSizePercentage, modeMaxFileSize, modeAllSections);

    if (!modeMaxFileSize) {
        addOverlay(sum_added_raw_size);
    }

    return sum_added_raw_size;
}

size_t RawSizeEditor::updateSectionHeaders(float rawSizePercentage , bool modeMaxFileSize, bool modeAllSections) {

    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << RED << "[!] Could not open file! (for editing raw size)"  << RESET<< std::endl;
        return 0;
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
    size_t sum_file_size = 0;
    for (auto& section : sectionHeaders) {
        sum_file_size += section.SizeOfRawData;
    }

    size_t sum_raw_size = 0;
    size_t section_size_tmp = 0;

    for (auto& section : sectionHeaders) {
        section_size_tmp = section.SizeOfRawData;

        // if raw size of section is 0, set it to 99% of the maximum raw size allowed
        if (section.SizeOfRawData <= 0) {
            if (modeMaxFileSize) {
                section.SizeOfRawData = static_cast<uint32_t>(sum_file_size * 0.99);
            }
            else {
                // convert to uint32_t 
                section.SizeOfRawData = static_cast<uint32_t>(section.Misc.VirtualSize + section.Misc.VirtualSize * rawSizePercentage);
            }
            sum_raw_size += section.SizeOfRawData;
            // print in hex
            if (section_size_tmp == section.SizeOfRawData) {
                std::cout << RED << "[+] Section " << section.Name << " raw size unchanged : 0x" << std::hex << section.SizeOfRawData << std::endl;
            }
            else {
                std::cout << GREEN <<"[+] \033[0m Section " << section.Name << " raw size updated to 0x" << std::hex << section.SizeOfRawData << std::endl;
                updated = true;
            }
        }
        else if (modeAllSections) {
            size_t rawSize = size_t(section.SizeOfRawData);
            section.SizeOfRawData = section.Misc.VirtualSize + (section.Misc.VirtualSize * rawSizePercentage);
            sum_raw_size += section.SizeOfRawData - rawSize;
            // print in hex
            std::cout << GREEN <<"[+]"<< RESET << " Section " << section.Name << " raw size updated to 0x" << std::hex << section.SizeOfRawData << std::endl;
            updated = true;
        }
    }

    std::ofstream outFile(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << RED << "Could not open file for writing!"<< RESET << std::endl;
        exit(1);
        return 0;
    }


    if (updated)
    {
        outFile.seekp(sectionHeadersOffset, std::ios::beg);
        outFile.write(reinterpret_cast<char*>(sectionHeaders.data()), sizeof(SectionHeader) * numberOfSections);
        std::cout << GREEN << "[+] Section raw size updated successfully!" << RESET << std::endl;
    }
    else {
        std::cout << RED << "[!] No change." << RESET << std::endl;
    }
    outFile.close();

    // Calculate the sum of the added raw size
    size_t sum_added_raw_size = sum_raw_size - sum_file_size;// - header_size;
    if (sum_added_raw_size < 0) {
        sum_added_raw_size = 0;
    }
    return sum_added_raw_size;
}