#include "LIEF/LIEF.hpp"
#include <iostream>



void rename_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string &section_name, const std::string &new_name) {
    // check if the section exists
    LIEF::PE::Section *section = binary->get_section(section_name);
    if (section == nullptr) {
        std::cerr << "Section \"" << section_name << "\" not found. \n Available sections:" << std::endl;
        for (const LIEF::PE::Section& sec : binary->sections()) {
            std::cout << " - " << sec.name() << std::endl;
        }
        throw std::runtime_error("Section not found");
        
        return;
    }
    // rename the section
    section->name(new_name);
}

void rename_section(LIEF::PE::Section& old_section, const std::string& new_name){
    old_section.name(new_name);
}

void rename_sections(std::unique_ptr<LIEF::PE::Binary>& binary, const std::vector<std::string> &section_names, const std::vector<std::string> &new_names) {
    for (size_t i = 0; i < section_names.size(); ++i) {
        rename_section(binary, section_names[i], new_names[i]);
    }
}