#include <LIEF/PE.hpp>

#include <vector>
#include <random>
#include <iostream>

#include "PEBinaryModifiers.hpp"

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
                                    size_t nb_pre_instructions, size_t nb_mid_instructions
                                    ) {
    if(characteristics == 0){
        characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE); 
    }
    auto& optional_header = binary->optional_header();
    uint64_t original_entrypoint = optional_header.addressof_entrypoint();// + optional_header.imagebase();

    //bool is_64bits = binary->optional_header().magic() == LIEF::PE::PE_TYPE::PE32_PLUS;

    std::vector<uint8_t> entrypoint_data = {0xE9}; // JMP rel32
    for (int i = 0; i < 4; ++i) {
        entrypoint_data.push_back((original_entrypoint >> (i*8)) & 0xFF);
    }
    //get_trampoline_instructions(original_entrypoint, nb_pre_instructions, nb_mid_instructions ,is_64bits);

    // Combine pre_data, trampoline, and post_data
    std::vector<uint8_t> section_data = pre_data;
    section_data.insert(section_data.end(), entrypoint_data.begin(), entrypoint_data.end());
    section_data.insert(section_data.end(), post_data.begin(), post_data.end());

    // Create and add the new section
    LIEF::PE::Section new_section;
    new_section.name(name);
    new_section.characteristics(characteristics);
    new_section.content(section_data);
    binary->add_section(new_section);

    //uint64_t offset_to_jmp = section_data.size() - post_data.size();

    LIEF::PE::Section* created_section = binary->get_section(name);
    if (created_section == nullptr) {
        std::cerr << "Failed to create section \"" << name << "\"" << std::endl;
        return;
    }
    //uint64_t offset_to_entrypoint = original_entrypoint - (created_section->virtual_address() + offset_to_jmp);
    int32_t offset = original_entrypoint - (created_section->virtual_address() + pre_data.size() + entrypoint_data.size());

    
    std::vector<uint8_t> new_entrypoint_data = {0xE9}; // JMP rel32
    for (int i = 0; i < 4; ++i) {
        new_entrypoint_data.push_back((offset >> (i*8)) & 0xFF);
    }

    std::vector<uint8_t> new_section_data = pre_data;
    new_section_data.insert(new_section_data.end(), new_entrypoint_data.begin(), new_entrypoint_data.end());
    new_section_data.insert(new_section_data.end(), post_data.begin(), post_data.end());

    created_section->content(new_section_data);

    // Update the entry point to point to the new section (pre_data + trampoline + post_data)
    optional_header.addressof_entrypoint(binary->get_section(name)->virtual_address() + pre_data.size());
}

// Function to move the entry point to slack_space of given section
void PEBinaryModifiers::move_entrypoint_to_slack_space(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name,
                                    size_t nb_pre_instructions, size_t nb_mid_instructions) {
    // TODO: test it
    
    LIEF::PE::OptionalHeader& optional_header = binary->optional_header();
    uint64_t original_entrypoint = optional_header.addressof_entrypoint() + optional_header.imagebase();

    
    LIEF::PE::Section* new_section = binary->get_section(section_name);

    bool is_64bits = binary->optional_header().magic() == LIEF::PE::PE_TYPE::PE32_PLUS;

    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(original_entrypoint, nb_pre_instructions, nb_mid_instructions, is_64bits);
    
    // calculate the slack space available in the section
    size_t slack_space = new_section->size() - new_section->content().size();
    if (entrypoint_data.size() > slack_space) {
        std::cerr << "Not enough slack space in the section for the entrypoint data. (value: " << entrypoint_data.size() << ", slack space: " << slack_space << ")" << std::endl;
        return;
    }else{
        std::cout << "Slack space available: " << slack_space << std::endl;
    }

    // calculate the current data size in the section
    size_t current_data_size = new_section->content().size();

    // Combine section.content data and trampoline
    std::vector<uint8_t> section_data(new_section->content().begin(), new_section->content().end());
    section_data.insert(section_data.end(), entrypoint_data.begin(), entrypoint_data.end());

    // Overwrite the section content with the new data
    new_section->content(section_data);

    // replace the section by removing and adding it again
    binary->remove_section(section_name);
    binary->add_section(*new_section);

    // Update the entry point to point to the new section
    optional_header.addressof_entrypoint(new_section->virtual_address() + current_data_size);
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
std::vector<uint8_t> PEBinaryModifiers::get_dummy_instructions(size_t count) {
    // Define an array of dummy instructions (equivalent to the ones in your Python example)
    const std::vector<std::vector<uint8_t>> dummy_instructions = {
        {0x90}, // NOP
        {0x87, 0xC0}, // XCHG EAX, EAX
        {0x83, 0xC0, 0x00}, // ADD EAX, 0
        {0x83, 0xE9, 0x00}, // SUB ECX, 0
        {0x89, 0xC2}, // MOV EDX, EDX
        {0x50, 0x58}, // PUSH EAX + POP EAX
        {0x8D, 0x1B}, // LEA EBX, [EBX]
        {0x81, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x81, 0xEF, 0x01, 0x00, 0x00, 0x00}, // ADD EDI, 1 + SUB EDI, 1
        {0x81, 0xE6, 0xFF, 0xFF, 0xFF, 0xFF}, // AND ESI, 0xFFFFFFFF
        {0x83, 0xCA, 0x00}, // OR EDX, 0
        {0xEB, 0x00}, // JMP SHORT $+2
        {0x33, 0xC0}, // XOR EAX, EAX
        {0x33, 0xC9}, // XOR ECX, ECX
        {0x33, 0xD2}, // XOR EDX, EDX
        {0x33, 0xDB}, // XOR EBX, EBX
        {0xD1, 0xC0}, // ROL EAX, 1
        {0x50, 0x58}, // PUSH EAX + POP EAX
        {0x05, 0x01, 0x00, 0x00, 0x00, 0x2D, 0x01, 0x00, 0x00, 0x00}, // ADD EAX, 1 + SUB EAX, 1
        {0xF9, 0xF8}, // STC + CLC
        {0x89, 0xC1, 0x89, 0xC8}, // MOV ECX, EAX + MOV EAX, ECX
        {0x8D, 0x80, 0x00, 0x00, 0x00, 0x00}, // LEA EAX, [EAX]
        {0x83, 0xC8, 0x00}, // OR EAX, 0
        {0xEB, 0x00, 0x90}, // JMP SHORT 2 bytes over NOP
        {0x50, 0x48, 0x89, 0xC1, 0x40, 0x58}, // PUSH EAX + DEC EAX + MOV ECX, EAX + INC EAX + POP EAX
    }; // 25 dummy instructions

    std::vector<uint8_t> instructions;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, dummy_instructions.size() - 1);

    for (size_t i = 0; i < count; ++i) {
        auto& selected = dummy_instructions[distr(gen)];
        instructions.insert(instructions.end(), selected.begin(), selected.end());
    }

    return instructions;
}


std::vector<uint8_t> PEBinaryModifiers::get_trampoline_instructions(uint64_t original_entrypoint, size_t nb_pre_instructions, size_t nb_mid_instructions, bool is_64bits) {
    std::vector<uint8_t> trampoline;
    trampoline.reserve(32); // Reserve some space to avoid frequent reallocations

    // Add dummy instructions at the beginning
    std::vector<uint8_t> pre_instructions = get_dummy_instructions(nb_pre_instructions);
    trampoline.insert(trampoline.end(), pre_instructions.begin(), pre_instructions.end());


    // Trampoline logic to jump back to the original entry point
    if (is_64bits) {
        trampoline.insert(trampoline.end(), {0x48, 0xB8}); // MOV RAX, <addr>
        for (int i = 0; i < 8; ++i) {
            trampoline.push_back((original_entrypoint >> (i*8)) & 0xFF); // the address of the original entry point
        }
        trampoline.insert(trampoline.end(), {0x50}); // PUSH RAX
    } else {
        trampoline.push_back(0x68); // PUSH <addr>
        // in little endian
        for (int i = 0; i < 4; ++i) {
            trampoline.push_back((original_entrypoint >> (i*8)) & 0xFF); // the address of the original entry point
        }
    }

    // Add dummy instructions in the middle
    std::vector<uint8_t> mid_instructions = get_dummy_instructions(nb_mid_instructions);
    trampoline.insert(trampoline.end(), mid_instructions.begin(), mid_instructions.end());

    // Add the RET instruction
    trampoline.push_back(0xC3); // RET


    return trampoline;
}
