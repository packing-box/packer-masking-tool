#ifndef PEBINARY_MODIFIERS_HPP
#define PEBINARY_MODIFIERS_HPP

#include "LIEF/PE.hpp"

#include <LIEF/LIEF.hpp>

#include <vector>
#include <random>
#include <iostream>


class PEBinaryModifiers {
public:
    static void add_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics=0,  LIEF::PE::PE_SECTION_TYPES type=LIEF::PE::PE_SECTION_TYPES::TEXT);

    static void rename_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string &section_name, const std::string &new_name);

    static void rename_section(LIEF::PE::Section& old_section, const std::string& new_name);

    static void rename_sections(std::unique_ptr<LIEF::PE::Binary>& binary, const std::vector<std::string> &section_names, const std::vector<std::string> &new_names);


    static bool append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data);

    // Function to move the entry point to a new section
    static void move_entrypoint_to_new_section(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                        const std::string& name, uint32_t characteristics=0,
                                        const std::vector<uint8_t>& pre_data={}, const std::vector<uint8_t>& post_data={},
                                        size_t nb_pre_instructions=5, size_t nb_mid_instructions=5
                                        );

    // Function to move the entry point to slack_space of given section
    static void move_entrypoint_to_slack_space(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name,
                                        size_t nb_pre_instructions=5, size_t nb_mid_instructions=5);

    static bool set_checksum(std::unique_ptr<LIEF::PE::Binary>& binary, uint32_t checksum);

    static void add_lib_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name);

    static void add_API_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name, const std::string& api_name);
// ==========================================
// ==========================================
// ================ PRIVATE =================
// ==========================================
// ==========================================
private:
    static bool _append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data_to_append);

    // Helper function to add dummy instructions
    static std::vector<uint8_t> get_dummy_instructions(size_t count);


    static std::vector<uint8_t> get_trampoline_instructions(uint64_t original_entrypoint, size_t nb_pre_instructions=5, size_t nb_mid_instructions=5, bool is_64bits=false);


};


#endif // PEBINARY_MODIFIERS_HPP