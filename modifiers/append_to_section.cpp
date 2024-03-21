#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>
#include <functional>

bool append_to_section(LIEF::PE::Binary& binary, const std::string& section_name, const std::vector<uint8_t>& data) {
    auto* section = binary.get_section(section_name);
    if (section == nullptr) {
        std::cerr << "Section \"" << section_name << "\" not found." << std::endl;
        return false;
    }

    uint32_t file_alignment = binary.optional_header().file_alignment();
    size_t section_content_length = section->content().size();
    size_t available_size = section->virtual_size() - section_content_length;

    std::vector<uint8_t> d = data; // Assume data is already provided or calculated elsewhere

    if (available_size == 0) {
        std::cerr << ">> " << section_name << ": no available space" << std::endl;
        return false;
    }
    else if (d.size() > available_size) {
        std::cerr << ">> " << section_name << ": truncating data (" << d.size() << " bytes) to " << available_size << " bytes" << std::endl;
        d.resize(available_size);
    }

    // When section's data and raw size are zero, LIEF fails to append data to the target section, hence in this case, we must handle separately.
    // However, this specific case handling is complex and may not be directly supported by LIEF's C++ API. You would typically rebuild the sections or modify content directly.
    // For the sake of simplicity and direct API usage, we'll append to the existing content and adjust sizes accordingly here.

    std::vector<uint8_t> new_content(section->content().begin(), section->content().end());
    new_content.insert(new_content.end(), d.begin(), d.end());
    section->content(new_content);

    // Adjust the section size to accommodate the new content, aligning according to file alignment
    size_t new_size = new_content.size() + ((file_alignment - (new_content.size() % file_alignment)) % file_alignment);
    section->size(new_size);

    // The virtual size should also be updated if necessary 
    if (new_size > section->virtual_size()) {
        section->virtual_size(new_size);
    }

    return true;
}


bool _append_to_section(LIEF::PE::Binary& binary, const std::string& section_name, const std::vector<uint8_t>& data_to_append) {
    LIEF::PE::Section* section_ptr = binary.get_section(section_name);
    if (section_ptr == nullptr) {
        std::cerr << "Section \"" << section_name << "\" not found." << std::endl;
        return false;
    }
    
    std::vector<uint8_t> content(section_ptr->content().begin(), section_ptr->content().end());

    // Calculate the available slack space
    size_t slack_space = section_ptr->size() - content.size();
    if (data_to_append.size() > slack_space) {
        std::cerr << "Not enough slack space in the section for the data." << std::endl;
        //return false;
        // extend slack space
        section_ptr->size(section_ptr->size() + data_to_append.size() - slack_space);
    }

    // Append the data to the section content
    content.insert(content.end(), data_to_append.begin(), data_to_append.end());

    section_ptr->content(content);

    // Update the section's characteristics if necessary
    // For example, if appending executable code, ensure the section is executable
    // section.characteristics(section.characteristics() | LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);

    return true;
}


/*
Usage: append_to_section(*binary, ".UPX1", {0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
*/