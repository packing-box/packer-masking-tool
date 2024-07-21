#include <LIEF/PE.hpp>

#include <vector>
#include <random>
#include <iostream>

#include "PEBinaryModifiers.hpp"
#include "PEBinary.hpp"


// class PEBinaryModifiers implementations
void PEBinaryModifiers::add_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics,  LIEF::PE::PE_SECTION_TYPES type) {
    LIEF::PE::Section section;
    section.name(name);
    if (characteristics == 0)
    {
        characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    }
    section.type(type);
    section.characteristics(characteristics);
    section.content(data);
    binary->add_section(section);
}

void PEBinaryModifiers::rename_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string &section_name, const std::string &new_name) {
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

    // check if the new name is already used
    if (binary->get_section(new_name) != nullptr){
        std::cerr << "Section name \"" << new_name << "\" already exists." << std::endl;
        return;
    }

    // check new name is smaller than 8 characters
    if (new_name.size() > 8){
        // TODO: handle this case (we should store \<offset> in the section name and update the references to it)
        std::cerr << "Section name \"" << new_name << "\" is longer than 8 characters." << std::endl;
        return;
    }

    // rename the section
    section->name(new_name);
}

void PEBinaryModifiers::rename_section(LIEF::PE::Section& old_section, const std::string& new_name){
    old_section.name(new_name);
}

void PEBinaryModifiers::rename_sections(std::unique_ptr<LIEF::PE::Binary>& binary, const std::vector<std::string> &section_names, const std::vector<std::string> &new_names) {
    for (size_t i = 0; i < section_names.size(); ++i) {
        rename_section(binary, section_names[i], new_names[i]);
    }
}


bool PEBinaryModifiers::append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data) {
    auto* section = binary->get_section(section_name);
    if (section == nullptr) {
        std::cerr << "Section \"" << section_name << "\" not found." << std::endl;
        return false;
    }

    uint32_t file_alignment = binary->optional_header().file_alignment();
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

// Function to move the entry point to a new section
void PEBinaryModifiers::move_entrypoint_to_new_section(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                    const std::string& name, uint32_t characteristics,
                                    const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data,
                                    size_t nb_deadcode
                                    ) {
    if(characteristics == 0){
        characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE); 
    }
    auto& optional_header = binary->optional_header();
    uint64_t original_entrypoint = optional_header.addressof_entrypoint();// + addressof_entrypoint (RVA)

    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(original_entrypoint, nb_deadcode);

    // Combine pre_data, trampoline, and post_data
    std::vector<uint8_t> section_data = pre_data;
    section_data.insert(section_data.end(), entrypoint_data.begin(), entrypoint_data.end());
    section_data.insert(section_data.end(), post_data.begin(), post_data.end());

    add_section(binary, name, section_data, characteristics);

    LIEF::PE::Section* created_section = binary->get_section(name);
    if (created_section == nullptr) {
        std::cerr << "Failed to create section \"" << name << "\"" << std::endl;
        return;
    }

    int32_t offset = original_entrypoint - (created_section->virtual_address() + pre_data.size() + entrypoint_data.size());
    
    // replace last 4 bytes of the trampoline with the offset
    for (int i = 0; i < 4; ++i) {
        entrypoint_data[entrypoint_data.size()-4+i] = (offset >> (i*8)) & 0xFF;
    }
    
    std::vector<uint8_t> new_section_data = pre_data;
    new_section_data.insert(new_section_data.end(), entrypoint_data.begin(), entrypoint_data.end());
    new_section_data.insert(new_section_data.end(), post_data.begin(), post_data.end());

    created_section->content(new_section_data);

    // Update the entry point to point to the new section (pre_data + trampoline + post_data)
    optional_header.addressof_entrypoint(binary->get_section(name)->virtual_address() + pre_data.size());
}

// Function to move the entry point to slack_space of given section
void PEBinaryModifiers::move_entrypoint_to_slack_space(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name,
                                    size_t nb_deadcode) {
    // TODO: test it
    
    LIEF::PE::OptionalHeader& optional_header = binary->optional_header();
    uint64_t original_entrypoint = optional_header.addressof_entrypoint(); // + addressof_entrypoint (RVA)

    
    LIEF::PE::Section* target_section = binary->get_section(section_name);
    if (target_section == nullptr) {
        std::cerr << "Section \"" << section_name << "\" not found." << std::endl;
        return;
    }

    // calculate the current data size in the section
    size_t current_data_size = target_section->content().size();
    int32_t offset = original_entrypoint - (target_section->virtual_address()+current_data_size + 5);
    // we set 5 as the size of the jump instruction 
    // (but if we decide to use deadcode, we should get trampoline code then use the size and replace last 4 bytes)

    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(offset, 0);

    // calculate the slack space available in the section
    size_t slack_space = target_section->size() - current_data_size;
    if (entrypoint_data.size() > slack_space) {
        std::cerr << "Not enough slack space in the section for the entrypoint data. (value: " << entrypoint_data.size() << ", slack space: " << slack_space << ")" << std::endl;
        return;
    }else{
        std::cout << "Slack space available: " << slack_space << std::endl;
    }

    
    // Combine section.content data and trampoline
    std::vector<uint8_t> section_data(target_section->content().begin(), target_section->content().end());
    section_data.insert(section_data.end(), entrypoint_data.begin(), entrypoint_data.end());

    // Overwrite the section content with the new data
    target_section->content(section_data);

    // replace the section by removing and adding it again
    binary->remove_section(section_name);
    binary->add_section(*target_section);

    // Update the entry point to point to the new section
    optional_header.addressof_entrypoint(target_section->virtual_address() + current_data_size);
}

bool PEBinaryModifiers::set_checksum(std::unique_ptr<LIEF::PE::Binary>& binary, uint32_t checksum) {
    binary->optional_header().checksum(checksum);
    return true;
}

void PEBinaryModifiers::add_lib_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name) {
    // if library is not imported, add it
    if (!binary->has_import(dll_name)) {
        binary->add_library(dll_name);
    }
}

void PEBinaryModifiers::add_API_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name, const std::string& api_name) {
    // if library is not imported, add it
    if (!binary->has_import(dll_name)) {
        binary->add_library(dll_name);
    }
    binary->add_import_function(dll_name, api_name);
}

// ==========================================
bool PEBinaryModifiers::_append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data_to_append) {
    LIEF::PE::Section* section_ptr = binary->get_section(section_name);
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

// Helper function to add dummy instructions
std::vector<uint8_t> PEBinaryModifiers::get_dead_code_instructions(size_t count) {

    std::vector<std::vector<uint8_t>> dead_code_instructions = PEBinary::get_dead_code_bytes();
    std::vector<uint8_t> instructions;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, dead_code_instructions.size() - 1);

    for (size_t i = 0; i < count; ++i) {
        auto& selected = dead_code_instructions[distr(gen)];
        instructions.insert(instructions.end(), selected.begin(), selected.end());
    }

    return instructions;
}


std::vector<uint8_t> PEBinaryModifiers::get_trampoline_instructions(uint64_t offset, size_t nb_deadcode) {
    std::vector<uint8_t> trampoline;
    trampoline.reserve(5+(nb_deadcode*2)); // Reserve some space to avoid frequent reallocations

    // Add dummy instructions at the beginning
    if(nb_deadcode > 0){
        std::vector<uint8_t> dead_code;
        // Add dead code after the entrypoint, before jumping to the original entrypoint
        // Generate a random number between 0 and 1
        if (std::rand() % 2 == 1) {
            // push ebp / mov ebp, esp
            dead_code.push_back(0x55);
            dead_code.push_back(0x8B);
            dead_code.push_back(0xEC);
        }
        
        // sub esp, 0xc
        dead_code.push_back(0x83);
        dead_code.push_back(0xEC);
        dead_code.push_back(0x0C);

        std::vector<uint8_t> _deadcode = get_dead_code_instructions(nb_deadcode);
        trampoline.insert(trampoline.end(), dead_code.begin(), dead_code.end());
        trampoline.insert(trampoline.end(), _deadcode.begin(), _deadcode.end());
    }


    // Trampoline logic to jump back to the original entry point
    // in little endian
    trampoline.push_back(0xE9);// JMP rel32
    for (int i = 0; i < 4; ++i) {
        trampoline.push_back((offset >> (i*8)) & 0xFF);
    }


    return trampoline;
}
