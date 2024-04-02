#include "LIEF/PE.hpp"
#include "PEBinary.hpp"
#include <iostream> // for std::cout
#include <sstream> // for std::stringstream
#include <iomanip> // for std::hex
#include <fstream> // for std::ifstream

#include "PEBinaryModifiers.hpp"

#include <cmath> // For std::round

// Helper function to convert std::u16string to std::string (UTF-8)
std::string u16string_to_utf8(const std::u16string& u16str) {
    // copy the u16string to a string
    std::string str;
    for (char16_t c : u16str) {
        str.push_back(static_cast<char>(c));
    }
    return str;
}



// =======================================
// CLASS PEBinary IMPLEMENTATION
// =======================================
// Constructor
PEBinary::PEBinary(const std::string& file) : filename(file),pe(LIEF::PE::Parser::parse(file)) {
    if (!pe) {
        throw std::runtime_error("Failed to parse the PE file: " + file);
    }
}
PEBinary::~PEBinary() {
    pe.reset(); // std::unique_ptr will delete the object
}
//PEBinary(std::unique_ptr<LIEF::PE::Binary> binary) : pe(binary) {}
// copy constructor
//PEBinary(const PEBinary& other) : pe(other.pe) {} // careful it is a shallow copy!

// Method to get the section where the entrypoint is located
LIEF::PE::Section* PEBinary::get_entrypoint_section() {
    // get the entrypoint
    uint64_t entrypoint = pe->optional_header().addressof_entrypoint();
    //entrypoint += pe->imagebase(); // TODO: check if this is correct

    // get the section where the entrypoint is located
    return pe->section_from_rva(entrypoint); // gives Segmentation fault

    // instead of using section_from_rva, iterate over the sections and check if the entrypoint is in the section
    /*for (LIEF::PE::Section& section : pe->sections()) {
        uint64_t section_start = section.virtual_address();
        uint64_t section_end = section_start + section.virtual_size();
        if (entrypoint >= section_start && entrypoint < section_end) {
            return &section;
        }
    }*/
    return nullptr;
}

std::unique_ptr<LIEF::PE::Binary>& PEBinary::get() {
    return pe;
}

// get optional header
LIEF::PE::OptionalHeader& PEBinary::get_optional_header() {
    return pe->optional_header();
}

// get size of the binary
uint64_t PEBinary::get_size() {
    return pe->original_size(); // ?? correct ?
}

//get api imports
std::vector<std::pair<std::string, std::string>> PEBinary::get_api_imports() {
    std::vector<std::pair<std::string, std::string>> api_imports;
    for (const LIEF::PE::Import& import : pe->imports()) {
        for (const LIEF::PE::ImportEntry& entry : import.entries()) {
            api_imports.push_back({import.name(), entry.name()});
        }
    }
    return api_imports;
}

// Assuming 'exe' is a PE binary object from the LIEF library
size_t PEBinary::calculate_size(double ratio, size_t blocksize) {
    // Calculate the scaled size and round to nearest blocksize
    size_t scaled_size = static_cast<size_t>(std::round((pe->original_size() * ratio) / blocksize + 0.5)) * blocksize;
    return scaled_size;
}

// get array of section names
std::vector<std::string> PEBinary::get_section_names() {
    std::vector<std::string> section_names;
    for (const LIEF::PE::Section& section : pe->sections()) {
        section_names.push_back(section.name());
    }
    return section_names;
}

//get sections 
std::vector<LIEF::PE::Section> PEBinary::get_sections() {
    std::vector<LIEF::PE::Section> sections;
    for (const LIEF::PE::Section& section : pe->sections()) {
        sections.push_back(section);
    }
    return sections;
}

// get array of empty section names
// real_name (in python) : _rn = lambda s: ensure_str(getattr(s, "real_name", s.name)).split("\0")[0]
std::vector<std::string> PEBinary::get_empty_name_sections() {
    /*
    def empty_name_sections(self):
        return [s for s in self if _rn(s) == ""]
    */
    std::vector<std::string> empty_name_sections;
    for (const LIEF::PE::Section& section : pe->sections()) {
        if (section.name() == "") {
            empty_name_sections.push_back(section.name());
        }
    }
    return empty_name_sections;
}

std::string PEBinary::offset_to_hex(uint64_t offset){
    std::stringstream ss;
    ss << std::hex << offset;
    std::string offset_section_hex_string = ss.str();
    // add padding to the string (to have 8 characters)
    offset_section_hex_string = std::string(8 - offset_section_hex_string.length(), '0') + offset_section_hex_string;
            
    return offset_section_hex_string;
}



// get array of real section names (of long sections names)
std::vector<std::string> PEBinary::get_real_section_names() {
    /* For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table */
    std::vector<std::string> real_name_sections;

    for (const LIEF::PE::Section& section : pe->sections()) {
        std::string name = section.name();
        // if name contains a slash "/" get the content after "/4" (for example, get 4)
        if (name.find("/") != std::string::npos) {
            std::cout << "Name: " << name << std::endl;
            std::string real_name = name;
            // get the offset in the string table (could not make it work .. so I use command line tool)
            //std::string ascii_decimal = name.substr(name.find("/") + 1);
            //const int offset = std::stoi(ascii_decimal); // 4 will be converted to 4

            std::string offset_section_hex_string = offset_to_hex(section.offset());
            
            // ======= Execute command 'objdump -h' to get the real names ====
            std::string command = "objdump -h " + this->filename + " | grep -P '\\d+.*\\s" + offset_section_hex_string + "\\s+' | cut -d ' ' -f4";
            
            real_name = execute_command(command);

            // get the real name from the string table
            real_name_sections.push_back(real_name);
        }else{
            real_name_sections.push_back(name);
        }
    }
    return real_name_sections;

}

std::vector<std::string> PEBinary::get_list_from_file(const std::string& filename) {
    std::vector<std::string> list;
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            // ignore empty lines and lines starting with #
            if (line.empty() || line[0] == '#') {
                continue;
            }
            // remove comments after the section name
            size_t comment_pos = line.find('#');
            if (comment_pos != std::string::npos) {
                line = line.substr(0, comment_pos);
            }
            // remove whitespace at the beginning and end of the line
            line = line.substr(line.find_first_not_of(" \t"));
            list.push_back(line);
        }
        file.close();
    }
    return list;
}

std::string PEBinary::get_permission_of_section(std::string section_name) {
    LIEF::PE::Section *section = pe->get_section(section_name);
    if (section == nullptr) {
        throw std::runtime_error("Section \"" + section_name + "\" not found.");
    }
    // get the permission of the section (read, write, execute)
    std::string permission = "---";
    if (section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) {
        permission[0] = 'r';
    }
    if (section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) {
        permission[1] = 'w';
    }
    if (section->has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) {
        permission[2] = 'x';
    }
    return permission;
}

std::vector<std::string> PEBinary::get_common_packer_section_names() {
    // get from common_packer_section_names.hpp
    #include "../definitions/common_packer_section_names.hpp"
    // this should be obfuscated or encrypted later
    return common_packer_section_names;
}

std::vector<std::string> PEBinary::get_standard_section_names() {
    #include "../definitions/standard_section_names.hpp"
    return standard_section_names;
}

std::vector<std::pair<std::string, std::string>> PEBinary::get_common_api_imports() {
    #include "../definitions/common_api_imports.hpp"
    return common_api_imports;
}



// modifiers:

void PEBinary::add_API_to_IAT(const std::pair<std::string, std::string>& api_import) {
    PEBinaryModifiers::add_API_to_IAT(pe, api_import.first, api_import.second);
}

void PEBinary::add_section( const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics, LIEF::PE::PE_SECTION_TYPES type) {
    // static call to add_section in PEBinaryModifiers
    PEBinaryModifiers::add_section(pe, name, data, characteristics, type);
}

void PEBinary::rename_section( const std::string &section_name, const std::string &new_name) {
    PEBinaryModifiers::rename_section(pe, section_name, new_name);
}

bool PEBinary::append_to_section( const std::string& section_name, const std::vector<uint8_t>& data){
    return PEBinaryModifiers::append_to_section(pe, section_name, data);
}

void PEBinary::move_entrypoint_to_new_section( const std::string& name, uint32_t characteristics, const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data) {
    
    PEBinaryModifiers::move_entrypoint_to_new_section(pe, name, characteristics, pre_data, post_data); // default = 5 pre mid instructions
}

void PEBinary::move_entrypoint_to_slack_space( const std::string& section_name, size_t nb_pre_instructions, size_t nb_mid_instructions) {
    PEBinaryModifiers::move_entrypoint_to_slack_space(pe, section_name, nb_pre_instructions, nb_mid_instructions);
}

bool PEBinary::set_checksum( uint32_t checksum) {
    return PEBinaryModifiers::set_checksum(pe, checksum);
}


std::string PEBinary::execute_command(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    std::cout << "Command: " << command << std::endl;
    std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    std::cout << "Result: " << result << std::endl;
    return result;
}
