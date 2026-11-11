#include <LIEF/PE.hpp>

#include <vector>
#include <random>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <cstdlib>  // For std::rand
#include <cctype>   // For std::tolower
#include "PEBinaryModifiers.hpp"
#include "PEBinary.hpp"
#include "Utilities.cpp"
#include "../definitions/common_section_permissions.hpp"
#include "constants.hpp"

// class PEBinaryModifiers implementations
void PEBinaryModifiers::add_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics) {
    LIEF::PE::Section section;
    section.name(name);
    if (characteristics == 0)
    {
        characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
    }
    // NOTE: LIEF 1.0.0 removed PE_SECTION_TYPES / Section::type(); a section is
    // now defined solely by its characteristics.
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

struct SectionData {
    std::string name;
    uint32_t virtual_address;
    uint32_t size;
    uint32_t virtual_size;
    uint32_t characteristics;
    std::vector<uint8_t> content;
    bool modified = false;
};


void PEBinaryModifiers::append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data) {
    LIEF::PE::Section* section = binary->get_section(section_name);
    if (!section) {
        std::cerr << "Section not found: " << section_name << std::endl;
        return;
    }

    size_t section_content_size = section->size();
    size_t section_virtual_size = section->virtual_size();
    size_t file_alignment = binary->optional_header().file_alignment();

    size_t available_size = (section_virtual_size > section_content_size) ? section_virtual_size - section_content_size : 0;
    std::vector<uint8_t> data_to_append = std::vector<uint8_t>(data.begin(), data.end());

    if (available_size == 0) {
        std::cerr << "[!] No available space in section: " << section_name << std::endl;
        return;
    } else if (data_to_append.size() > available_size) {
        data_to_append.resize(available_size);
        std::cerr << "[.] Truncating data to fit available space: " << available_size << " bytes" << std::endl;
    }

    if (section_content_size == 0 && section->size() == 0) {

        std::vector<SectionData> sections_data;
        std::vector<LIEF::PE::Section> sections;
        std::vector<LIEF::PE::Section> sections_current = std::vector<LIEF::PE::Section>(binary->sections().begin(), binary->sections().end());
        // sort sections by virtual address
        std::sort(sections_current.begin(), sections_current.end(), [](const LIEF::PE::Section& a, const LIEF::PE::Section& b) {
            return a.virtual_address() < b.virtual_address();
        });
        for (LIEF::PE::Section& s : sections_current) {
            sections.push_back(s);
        }

        // remove_all_sections (in reverse order)
        std::reverse(sections_current.begin(), sections_current.end());
        for (LIEF::PE::Section& s : sections_current) {
            binary->remove_section(s.name());
        }

        size_t point_to_raw_data = 0;
        for (LIEF::PE::Section& sd : sections) {
            if (sd.name() == section_name) {
                // align the section size to file alignment
                size_t new_size = sd.size() + data_to_append.size();
                sd.size(new_size + ((file_alignment - (new_size % file_alignment)) % file_alignment));
                // append the data to the section content
                sd.content(data_to_append);
            }

            if(point_to_raw_data == 0){
                point_to_raw_data = sd.pointerto_raw_data();
            }else{
                sd.pointerto_raw_data(point_to_raw_data);
            }
            point_to_raw_data += sd.size();
            if(point_to_raw_data % file_alignment != 0){
                point_to_raw_data += file_alignment - (point_to_raw_data % file_alignment);
            }
            binary->add_section(sd);            
        }
    } else {
        LIEF::span<const u_int8_t> section_content_tmp = section->content();
        std::vector<uint8_t> section_content(section_content_tmp.begin(), section_content_tmp.end());
        // Append the data to the section content
        section_content.insert(section_content.end(), data_to_append.begin(), data_to_append.end());
        size_t new_size = section_content.size();
        section->content(section_content);
        section->size(new_size);
    }
}

bool xappend_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data) {
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

    bool is_64_bit = binary->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64;
    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(original_entrypoint, nb_deadcode, true, is_64_bit);

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

void PEBinaryModifiers::fix_checksum(const std::string& file_path) {
    // Must run on the written file: LIEF's compute_checksum() on the in-memory
    // Binary returns the pre-modification value, so the checksum is recomputed
    // from the final on-disk bytes and patched directly into the header.
    std::unique_ptr<LIEF::PE::Binary> pe = LIEF::PE::Parser::parse(file_path);
    if (pe == nullptr) {
        return;
    }
    // User-mode EXEs are normally shipped with a zero checksum; only a non-zero
    // checksum has been invalidated by our modifications and needs recomputing.
    if (pe->optional_header().checksum() == 0) {
        return;
    }
    uint32_t checksum = pe->compute_checksum();

    std::fstream f(file_path, std::ios::in | std::ios::out | std::ios::binary);
    if (!f) {
        return;
    }
    // The checksum field lives at OptionalHeader offset 0x40, i.e. e_lfanew + 0x58
    // (PE signature 4 + COFF header 20 + 0x40), identical for PE32 and PE32+.
    uint32_t e_lfanew = 0;
    f.seekg(0x3C);
    f.read(reinterpret_cast<char*>(&e_lfanew), sizeof(e_lfanew));
    f.seekp(static_cast<std::streamoff>(e_lfanew) + 0x58);
    f.write(reinterpret_cast<const char*>(&checksum), sizeof(checksum));
}

void PEBinaryModifiers::add_lib_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name) {
    // if library is not imported, add it
    if (!binary->has_import(dll_name)) {
        binary->add_import(dll_name);
    }
}

void PEBinaryModifiers::add_API_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name, const std::string& api_name) {
    // LIEF 1.0.0: add_library/add_import_function were replaced by
    // add_import(dll) -> Import& and Import::add_entry(api).
    // Match the DLL case-insensitively so we extend the existing import
    // descriptor rather than creating a duplicate one (e.g. a file that
    // already imports "kernel32.dll" when we ask for "KERNEL32.DLL").
    auto iequals = [](const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i])) return false;
        }
        return true;
    };

    LIEF::PE::Import* import_ = nullptr;
    for (LIEF::PE::Import& imp : binary->imports()) {
        if (iequals(imp.name(), dll_name)) { import_ = &imp; break; }
    }
    if (import_ == nullptr) {
        import_ = &binary->add_import(dll_name);
    }

    // Don't add an API that the descriptor already imports.
    for (const LIEF::PE::ImportEntry& e : import_->entries()) {
        if (e.name() == api_name) return;
    }
    import_->add_entry(api_name);
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
std::vector<uint8_t> PEBinaryModifiers::get_dead_code_instructions(size_t count, bool is_64_bit) {

    std::vector<std::vector<uint8_t>> dead_code_instructions = PEBinary::get_dead_code_bytes(is_64_bit);
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


std::vector<uint8_t> PEBinaryModifiers::get_trampoline_instructions(uint64_t offset, size_t nb_deadcode, bool use_jump, bool is_64_bit) {
    std::vector<uint8_t> trampoline;
    trampoline.reserve(5+(nb_deadcode*2)); // Reserve some space to avoid frequent reallocations

    // Add dummy instructions at the beginning
    if(nb_deadcode > 0){
        std::vector<uint8_t> dead_code;
        // Add dead code after the entrypoint, before jumping to the original entrypoint
        // Generate a random number between 0 and 100 (seeded, so trampolines vary per run)
        static std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<> distr(0, 100);
        int random_number = distr(gen);
        bool inject_typical_byte_infront = random_number < 70;
        bool using_prolog = random_number < 15;

        if (inject_typical_byte_infront) {
            if (is_64_bit) {
                if (using_prolog) {
                    // push rbp / mov rbp, rsp
                    dead_code.insert(dead_code.end(), {0x55, 0x48, 0x89, 0xE5});
                }
                // sub rsp, 0x20
                dead_code.insert(dead_code.end(), {0x48, 0x83, 0xEC, 0x20});
            } else {
                if (using_prolog) {
                    // push ebp / mov ebp, esp
                    dead_code.insert(dead_code.end(), {0x55, 0x8B, 0xEC});
                }
                // sub esp, 0xc
                dead_code.insert(dead_code.end(), {0x83, 0xEC, 0x0C});
            }
        }

        std::vector<uint8_t> _deadcode = get_dead_code_instructions(nb_deadcode, is_64_bit);
        trampoline.insert(trampoline.end(), dead_code.begin(), dead_code.end());
        trampoline.insert(trampoline.end(), _deadcode.begin(), _deadcode.end());
    }


    // Trampoline logic to jump back to the original entry point
    // in little endian
    std::vector<uint8_t> offset_bytes = Utilities::to_little_endian_bytes_array(offset, false);
    if (use_jump) {
        trampoline.push_back(0xE9); // JMP rel32
        trampoline.insert(trampoline.end(), offset_bytes.begin(), offset_bytes.end());
    } else {
        trampoline.push_back(0xE8); // CALL rel32
        trampoline.insert(trampoline.end(), offset_bytes.begin(), offset_bytes.end());
    }


    return trampoline;
}




void PEBinaryModifiers::move_ep_to_new_section(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                    const std::string& name,
                                    uint32_t characteristics,
                                    const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data,
                                    size_t nb_deadcode,
                                    uint32_t offset_jmp,
                                    bool use_jump
                                    ) {
    if(characteristics == 0){
        characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE); 
    }

    bool is_64_bit = binary->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64;
    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(0, nb_deadcode, use_jump, is_64_bit);

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

    if(offset_jmp == 0){
        offset_jmp = binary->optional_header().addressof_entrypoint() - (created_section->virtual_address() + pre_data.size() + entrypoint_data.size());
    }

    // replace last 4 bytes of the trampoline with the offset
    for (int i = 0; i < 4; ++i) {
        entrypoint_data[entrypoint_data.size()-4+i] = (offset_jmp >> (i*8)) & 0xFF;
    }
    
    std::vector<uint8_t> new_section_data = pre_data;
    new_section_data.insert(new_section_data.end(), entrypoint_data.begin(), entrypoint_data.end());
    new_section_data.insert(new_section_data.end(), post_data.begin(), post_data.end());

    created_section->content(new_section_data);

    // Update the entry point to point to the new section (pre_data + trampoline + post_data)
    binary->optional_header().addressof_entrypoint(binary->get_section(name)->virtual_address() + pre_data.size());
}


// Function to move the entry point to a new section
void PEBinaryModifiers::update_section_permissions(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                    const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data,
                                    size_t nb_deadcode
                                    ) {
    uint32_t characteristics = static_cast<u_int32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ | LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE | LIEF::PE::Section::CHARACTERISTICS::CNT_CODE); 
    std::string name = ".text";
    uint64_t oep = binary->optional_header().addressof_entrypoint();
    
    bool is_64_bit = binary->header().machine() == LIEF::PE::Header::MACHINE_TYPES::AMD64;


    std::vector<uint8_t> bytes_to_add;
    uint32_t virtual_protect_address = get_virtual_protect_address(*binary);


    std::vector<std::pair<LIEF::PE::Section*, uint32_t>>  section_edited_permissions = rename_section_and_update_permissions(*binary);
    for (std::pair<LIEF::PE::Section*, uint32_t> section_tuple : section_edited_permissions) {
        LIEF::PE::Section* section = section_tuple.first;
        uint32_t original_characteristic = section_tuple.second;
        std::vector<uint8_t>  add_bytes = call_virtualProtect(
            virtual_protect_address, section->virtual_address(), section->virtual_size(),
            characteristic_to_vp_flag(original_characteristic), is_64_bit
        );
        bytes_to_add.insert(bytes_to_add.end(), add_bytes.begin(), add_bytes.end());
    }

    // Adding a new section
    std::vector<uint8_t> pre_data_trampoline = Utilities::append_vectors( Utilities::append_vectors(get_code_for_image_base(0), bytes_to_add) , trampoline_jmp(0));


    // use get_trampoline_instructions
    std::vector<uint8_t> obfuscated_trampoline = get_trampoline_instructions(0, nb_deadcode, false, is_64_bit);

    uint32_t offset_to_second_ep = (pre_data_trampoline.size() + obfuscated_trampoline.size());
    uint32_t neg_offset_to_second_ep = -offset_to_second_ep;
    // replace last 4 bytes of the trampoline with the offset
    for (int i = 0; i < 4; ++i) {
        obfuscated_trampoline[obfuscated_trampoline.size()-4+i] = (neg_offset_to_second_ep >> (i*8)) & 0xFF;
    }


    std::vector<uint8_t> left_wing = Utilities::append_vectors(pre_data, pre_data_trampoline);
    std::vector<uint8_t> right_wing = Utilities::append_vectors(obfuscated_trampoline, post_data);

    add_section(binary, name, Utilities::append_vectors(left_wing, right_wing), characteristics);

    // Ensure the section is correctly added
    LIEF::PE::Section* added_section = binary->get_section(name);
    if (added_section == nullptr) {
        std::cerr << "Failed to create section \"" << name << "\"" << std::endl;
        return;
    }

    // + pre_data.size() 
    uint32_t jmp_code_RVA = added_section->virtual_address() + pre_data.size() + pre_data_trampoline.size() + obfuscated_trampoline.size();

    // + pre_data.size() 
    uint32_t offset = oep - (added_section->virtual_address()+ pre_data.size() + pre_data_trampoline.size());
    pre_data_trampoline = Utilities::append_vectors( Utilities::append_vectors(get_code_for_image_base(jmp_code_RVA), bytes_to_add), trampoline_jmp(offset));

    left_wing = Utilities::append_vectors(pre_data, pre_data_trampoline);
    right_wing = Utilities::append_vectors(obfuscated_trampoline, post_data);

    added_section->content( Utilities::append_vectors(left_wing, right_wing));

    // Update entry point
    binary->optional_header().addressof_entrypoint(added_section->virtual_address()+ pre_data.size()  + pre_data_trampoline.size());
}


std::vector<uint8_t> PEBinaryModifiers::get_code_for_image_base(uint32_t rva) {
    // Recover the image base into EDI/RDI (what call_virtualProtect reads via
    // ADD EAX,EDI / ADD RAX,RDI). The trampoline is entered by a CALL, so the
    // return address on the stack is the runtime VA of the point whose compile
    // -time RVA is `rva`; popping it and subtracting `rva` yields the base.
    //
    // This used to be a single constant encoding (5B B8 <rva> 29 C3 8B FB),
    // which let a YARA/AV rule fingerprint NotPacked++ itself. Emit one of
    // several semantically-equivalent encodings instead (different scratch
    // registers / instructions). The variant is chosen once per run so the
    // sizing pass and the real emission agree on length, while the stub still
    // differs from one run to the next.
    static std::mt19937 variant_gen(std::random_device{}());
    static const int variant = std::uniform_int_distribution<>(0, 5)(variant_gen);

    std::vector<uint8_t> rva_bytes = Utilities::to_little_endian_bytes_array(rva);
    uint32_t neg_rva = static_cast<uint32_t>(-static_cast<int32_t>(rva));
    std::vector<uint8_t> neg_rva_bytes = Utilities::to_little_endian_bytes_array(neg_rva);

    std::vector<uint8_t> code;
    switch (variant) {
        case 1: // pop edi ; sub edi, rva
            code = {0x5F, 0x81, 0xEF};
            code.insert(code.end(), rva_bytes.begin(), rva_bytes.end());
            break;
        case 2: // pop edi ; add edi, -rva
            code = {0x5F, 0x81, 0xC7};
            code.insert(code.end(), neg_rva_bytes.begin(), neg_rva_bytes.end());
            break;
        case 3: // pop ecx ; mov eax, rva ; sub ecx, eax ; mov edi, ecx
            code = {0x59, 0xB8};
            code.insert(code.end(), rva_bytes.begin(), rva_bytes.end());
            code.insert(code.end(), {0x29, 0xC1, 0x8B, 0xF9});
            break;
        case 4: // pop ebx ; lea edi, [ebx - rva]
            code = {0x5B, 0x8D, 0xBB};
            code.insert(code.end(), neg_rva_bytes.begin(), neg_rva_bytes.end());
            break;
        case 5: // pop edx ; mov eax, rva ; sub edx, eax ; mov edi, edx
            code = {0x5A, 0xB8};
            code.insert(code.end(), rva_bytes.begin(), rva_bytes.end());
            code.insert(code.end(), {0x29, 0xC2, 0x8B, 0xFA});
            break;
        default: // case 0 (original): pop ebx ; mov eax, rva ; sub ebx, eax ; mov edi, ebx
            code = {0x5B, 0xB8};
            code.insert(code.end(), rva_bytes.begin(), rva_bytes.end());
            code.insert(code.end(), {0x29, 0xC3, 0x8B, 0xFB});
            break;
    }
    return code;
}


// Function to generate the assembly instructions for calling VirtualProtect
std::vector<uint8_t> PEBinaryModifiers::call_virtualProtect(uint64_t vp_address, uint64_t address, uint64_t size, uint32_t vp_flag, bool is_64_bit) {
    std::vector<uint8_t> bytes_array;

    //TODO: this part also needs randomization (deadcode insertion)
    if (is_64_bit) {
        // 64-bit code
        bytes_array = {
            // Allocate space on the stack for lpflOldProtect by subtracting 8 from RSP
            0x48, 0x83, 0xEC, 0x08, // SUB RSP, 8

            // 1. lpflOldProtect (passed in R9)
            0x49, 0x89, 0xE1, // MOV R9, RSP

            // 2. flNewProtect = vp_flag (0x40) (passed in R8D)
            0x41, 0xB8, // MOV R8D, vp_flag
        };
        std::vector<uint8_t> vp_flag_bytes = Utilities::to_little_endian_bytes_array(vp_flag);
        bytes_array.insert(bytes_array.end(), vp_flag_bytes.begin(), vp_flag_bytes.end());

        // 3. dwSize = size (passed in RDX)
        bytes_array.insert(bytes_array.end(), {0x48, 0xC7, 0xC2}); // MOV RDX, size
        std::vector<uint8_t> size_bytes = Utilities::to_little_endian_bytes_array(size);
        bytes_array.insert(bytes_array.end(), size_bytes.begin(), size_bytes.end());

        // 4. lpAddress = address (passed in RCX)
        bytes_array.insert(bytes_array.end(), {0x48, 0xB9}); // MOV RCX, address
        std::vector<uint8_t> address_bytes = Utilities::to_little_endian_bytes_array(address);
        bytes_array.insert(bytes_array.end(), address_bytes.begin(), address_bytes.end());

        // 5. Call VirtualProtect
        bytes_array.insert(bytes_array.end(), {0x48, 0xB8}); // MOV RAX, vp_address
        std::vector<uint8_t> vp_address_bytes = Utilities::to_little_endian_bytes_array(vp_address);
        bytes_array.insert(bytes_array.end(), vp_address_bytes.begin(), vp_address_bytes.end());
        bytes_array.insert(bytes_array.end(), {0x48, 0x01, 0xF8}); // ADD RAX, RDI
        bytes_array.insert(bytes_array.end(), {0xFF, 0xD0}); // CALL RAX
        bytes_array.insert(bytes_array.end(), {0x48, 0x83, 0xC4, 0x08}); // ADD RSP, 8

    } else {
        // 32-bit code
        bytes_array = {
            // Allocate space on the stack for lpflOldProtect by subtracting 4 from ESP
            0x83, 0xEC, 0x04, // SUB ESP, 4

            // 1. lpflOldProtect (PUSH ESP)
            0x54, // PUSH ESP

            // 2. flNewProtect = vp_flag (0x40)
            0x68 // PUSH vp_flag
        };
        std::vector<uint8_t> vp_flag_bytes = Utilities::to_little_endian_bytes_array(vp_flag);
        bytes_array.insert(bytes_array.end(), vp_flag_bytes.begin(), vp_flag_bytes.end());

        // 3. dwSize = size (PUSH size)
        bytes_array.insert(bytes_array.end(), {0x68}); // PUSH
        std::vector<uint8_t> size_bytes = Utilities::to_little_endian_bytes_array(size);
        bytes_array.insert(bytes_array.end(), size_bytes.begin(), size_bytes.end());

        // 4. lpAddress = address (PUSH address)
        bytes_array.insert(bytes_array.end(), {0xB8}); // MOV EAX, address
        std::vector<uint8_t> address_bytes = Utilities::to_little_endian_bytes_array(address);
        bytes_array.insert(bytes_array.end(), address_bytes.begin(), address_bytes.end());
        bytes_array.insert(bytes_array.end(), {0x01, 0xF8}); // ADD EAX, EDI
        bytes_array.insert(bytes_array.end(), {0x50}); // PUSH EAX

        // 5. hProcess = vp_address (PUSH vp_address)
        bytes_array.insert(bytes_array.end(), {0xB8});
        std::vector<uint8_t> vp_address_bytes = Utilities::to_little_endian_bytes_array(vp_address);
        bytes_array.insert(bytes_array.end(), vp_address_bytes.begin(), vp_address_bytes.end());
        bytes_array.insert(bytes_array.end(), {0x01, 0xF8}); // ADD EAX, EDI
        bytes_array.insert(bytes_array.end(), {0xFF, 0x10}); // CALL DWORD PTR DS:[EAX]
    }

    return bytes_array;
}


uint32_t PEBinaryModifiers::characteristic_to_vp_flag(uint32_t characteristics) {
    // Check the most permissive combination to the least
    if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) {
        if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) {
            return 0x40;  // PAGE_EXECUTE_READWRITE
        } else if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) {
            return 0x20;  // PAGE_EXECUTE_READ
        } else {
            return 0x10;  // PAGE_EXECUTE
        }
    } else if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) {
        return 0x04;  // PAGE_READWRITE
    } else if (characteristics & static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) {
        return 0x02;  // PAGE_READONLY
    }

    // Default to PAGE_EXECUTE_READWRITE if no other flags match
    return 0x40;  // Default rwx : PAGE_EXECUTE_READWRITE
}

std::vector<uint8_t> PEBinaryModifiers::trampoline_call(int32_t oep_or_offset) {
    std::vector<uint8_t> result = {0xE8}; // Call opcode
    std::vector<uint8_t> offset_bytes = Utilities::to_little_endian_bytes_array(oep_or_offset);
    result.insert(result.end(), offset_bytes.begin(), offset_bytes.end());
    return result;
}

std::vector<uint8_t> PEBinaryModifiers::trampoline_jmp(int32_t oep_or_offset) {
    std::vector<uint8_t> result = {0xE9}; // Jump opcode
    std::vector<uint8_t> offset_bytes = Utilities::to_little_endian_bytes_array(oep_or_offset);
    result.insert(result.end(), offset_bytes.begin(), offset_bytes.end());
    return result;
}


uint64_t PEBinaryModifiers::get_virtual_protect_address(LIEF::PE::Binary& pe) {
    // Check if 'VirtualProtect' is already in imports
    for (const auto& import_ : pe.imports()) {
        for (const auto& entry : import_.entries()) {
            if (entry.name() == "VirtualProtect") {
                return entry.iat_address();
            }
        }
    }

    // Find or add 'kernel32.dll' import
    LIEF::PE::Import* kernel32 = nullptr;
    for (auto& import_ : pe.imports()) {
        if (import_.name().size() > 0 && import_.name().compare("kernel32.dll") == 0) {
            kernel32 = &import_;
            break;
        }
    }

    if (kernel32 == nullptr) {
        kernel32 = &pe.add_import("KERNEL32.DLL");
    }

    // Add 'VirtualProtect' to 'kernel32.dll' and get its import entry
    auto& virtual_protect_entry = kernel32->add_entry("VirtualProtect");
    return virtual_protect_entry.iat_address();
}




// Check if a name is already used in the used names set
bool PEBinaryModifiers::is_name_used(const std::string& name, const std::unordered_set<std::string>& used_names) {
    return used_names.find(name) != used_names.end();
}

std::vector<std::pair<LIEF::PE::Section*, uint32_t>> PEBinaryModifiers::rename_section_and_update_permissions(LIEF::PE::Binary& binary) {
        std::vector<std::pair<LIEF::PE::Section*, uint32_t>> sections_edited;
        std::unordered_set<std::string> already_used = {".text"}; // Initialize with default used names
        std::vector<std::string> available_choices;

        // add current section names to already_used
        for (const auto& section : binary.sections()) {
            already_used.insert(section.name());
        }

        // Mapping from names to characteristics for fast lookup
        std::unordered_map<std::string, LIEF::PE::Section::CHARACTERISTICS> permissions_map;
        for (const auto& [name, characteristics] : common_sections_permissions) {
            permissions_map[name] = characteristics;
            if (!is_name_used(name, already_used)) {
                available_choices.push_back(name);
            }
        }

        for (auto& section : binary.sections()) {
            uint32_t original_characteristics = section.characteristics();
            auto it = permissions_map.find(section.name());
            if (it != permissions_map.end()) {
                if (section.characteristics() != static_cast<uint32_t>(it->second)) {
                    sections_edited.push_back(std::make_pair(&section, original_characteristics));
                    section.characteristics(static_cast<uint32_t>(it->second));
                }
            } else {
                // Find a new name not already used
                std::string chosen_name;
                for (auto& name : available_choices) {
                    // Could optimize by searching by permissions 
                    // (section already having same perm. than a standard section) so we only need to rename
                    if (!is_name_used(name, already_used)) {
                        chosen_name = name;
                        break;
                    }
                }

                if (chosen_name.empty()) {
                    std::cout << "No more choices of section names available to rename" << std::endl;
                    break;
                }

                std::cout << GREEN << "[+]"<< RESET <<" Renaming section " << section.name() << " to " << chosen_name << std::endl;
                section.name(chosen_name);
                already_used.insert(chosen_name);

                // Remove the chosen name from available choices
                available_choices.erase(std::remove(available_choices.begin(), available_choices.end(), chosen_name), available_choices.end());

                // Update permissions if different
                auto perm_it = permissions_map.find(chosen_name);
                if (perm_it != permissions_map.end() && section.characteristics() != static_cast<uint32_t>(perm_it->second)) {
                    sections_edited.push_back(std::make_pair(&section, original_characteristics));
                    section.characteristics(static_cast<uint32_t>(perm_it->second));
                }
            }
        }

        return sections_edited;
    }




