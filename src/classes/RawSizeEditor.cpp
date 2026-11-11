#include "RawSizeEditor.hpp"
#include "constants.hpp"
#include "CustomParser.hpp"
#include <random>

RawSizeEditor::RawSizeEditor(std::string filePath) : filePath(filePath), parser(filePath) {
    parser.parse();
}

void RawSizeEditor::addOverlay(size_t overlaySize) {
    if (overlaySize == 0) {
        std::cout << RED << "[!] No overlay to add (0)." << RESET << std::endl;
        return;
    }
    size_t MAX_VECTOR_SIZE = std::vector<u_int8_t>().max_size();
    if(overlaySize > MAX_VECTOR_SIZE){
        std::cerr << RED << "[!] Overlay size too large!" << RESET << std::endl;
        return;
    }
    

    std::vector<u_int8_t>& fileContents = parser.getFileContents();
    // A constant fill (the old 0x42 'BBBB...' run) is a trivially matchable
    // NotPacked++ signature. Use a short per-run-random repeating pattern
    // instead: still low entropy (3 distinct bytes, so it does not raise the
    // overlay's entropy) but with no fixed byte signature across runs.
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    uint8_t pattern[3] = {
        static_cast<uint8_t>(dist(gen)),
        static_cast<uint8_t>(dist(gen)),
        static_cast<uint8_t>(dist(gen))
    };
    std::vector<char> buffer(overlaySize);
    for (size_t i = 0; i < overlaySize; ++i) {
        buffer[i] = static_cast<char>(pattern[i % 3]);
    }
    fileContents.insert(fileContents.end(), buffer.begin(), buffer.end());

    parser.write(filePath);
    
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

    std::vector<SectionHeader>& sectionHeaders = parser.getSectionHeaders();

    bool updated = false;
    size_t sum_file_size = 0;
    for (SectionHeader& section : sectionHeaders) {
        sum_file_size += section.SizeOfRawData;
    }

    size_t sum_raw_size = 0;
    size_t section_size_tmp = 0;

    for (SectionHeader& section : sectionHeaders) {
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

    if (updated)
    {
        parser.write(filePath);
        std::cout << GREEN << "[+] Section raw size updated successfully!" << RESET << std::endl;
    }
    else {
        std::cout << RED << "[!] No change." << RESET << std::endl;
    }

    // Calculate the sum of the added raw size
    size_t sum_added_raw_size = sum_raw_size - sum_file_size;// - header_size;
    if (sum_added_raw_size < 0) {
        sum_added_raw_size = 0;
    }
    return sum_added_raw_size;
}
