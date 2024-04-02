#ifndef PEBINARY_HPP
#define PEBINARY_HPP

#include "LIEF/PE.hpp"
#include <string>
#include <vector>
#include <memory>


std::string u16string_to_utf8(const std::u16string& u16str);

class PEBinary {
public:
    PEBinary(const std::string& file);
    ~PEBinary();
    LIEF::PE::Section* get_entrypoint_section();
    std::unique_ptr<LIEF::PE::Binary>& get();
    LIEF::PE::OptionalHeader& get_optional_header();
    uint64_t get_size();
    std::vector<std::pair<std::string, std::string>> get_api_imports();
    size_t calculate_size(double ratio = 0.1, size_t blocksize = 512);
    std::vector<std::string> get_section_names();
    std::vector<LIEF::PE::Section> get_sections();
    std::vector<std::string> get_empty_name_sections();
    std::string offset_to_hex(uint64_t offset);
    std::vector<std::string> get_real_section_names();
    std::vector<std::string> get_list_from_file(const std::string& filename);
    std::string get_permission_of_section(std::string section_name);
    std::vector<std::string> get_common_packer_section_names();
    std::vector<std::string> get_standard_section_names();
    std::vector<std::pair<std::string, std::string>> get_common_api_imports();
    void add_API_to_IAT(const std::pair<std::string, std::string>& api_import);
    void add_section(const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics=0, LIEF::PE::PE_SECTION_TYPES type=LIEF::PE::PE_SECTION_TYPES::TEXT);
    void rename_section(const std::string &section_name, const std::string &new_name);
    bool append_to_section(const std::string& section_name, const std::vector<uint8_t>& data);
    void move_entrypoint_to_new_section(const std::string& name, uint32_t characteristics=0, const std::vector<uint8_t>& pre_data={}, const std::vector<uint8_t>& post_data={});
    void move_entrypoint_to_slack_space(const std::string& section_name, size_t nb_pre_instructions, size_t nb_mid_instructions);
    bool set_checksum(uint32_t checksum);

private:
    std::string filename;
    std::unique_ptr<LIEF::PE::Binary> pe;
    std::string execute_command(const std::string& command);
};

#endif // PEBINARY_HPP
