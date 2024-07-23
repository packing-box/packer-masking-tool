#ifndef PEBINARY_MODIFIERS_HPP
#define PEBINARY_MODIFIERS_HPP

#include "LIEF/PE.hpp"

#include <LIEF/LIEF.hpp>

#include <vector>
#include <random>
#include <iostream>
#include <unordered_set>



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
                                        size_t nb_deadcode=128
                                        );

    // Function to move the entry point to slack_space of given section
    static void move_entrypoint_to_slack_space(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name,
                                        size_t nb_deadcode=5);

    static bool set_checksum(std::unique_ptr<LIEF::PE::Binary>& binary, uint32_t checksum);

    static void add_lib_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name);

    static void add_API_to_IAT(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& dll_name, const std::string& api_name);

    static void update_section_permissions(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                    const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data,
                                    size_t nb_deadcode
                                    );

// ==========================================
// ==========================================
// ================ PRIVATE =================
// ==========================================
// ==========================================
private:
    static bool _append_to_section(std::unique_ptr<LIEF::PE::Binary>& binary, const std::string& section_name, const std::vector<uint8_t>& data_to_append);


    // Helper function to add dummy instructions
    static std::vector<uint8_t> get_dead_code_instructions(size_t count);


    static std::vector<uint8_t> get_trampoline_instructions(uint64_t original_entrypoint, size_t nb_deadcode=128,  bool use_jump=true);

    static std::vector<uint8_t> call_virtualProtect(uint64_t vp_address, uint64_t address, uint64_t size, uint32_t vp_flag = 0x40, bool is_64_bit = false);

    static uint32_t characteristic_to_vp_flag(uint32_t characteristics);

    static void move_ep_to_new_section(std::unique_ptr<LIEF::PE::Binary>& binary, 
                                    const std::string& name,
                                    uint32_t characteristics=0,
                                    const std::vector<uint8_t>& pre_data={}, 
                                    const std::vector<uint8_t>& post_data={},
                                    size_t nb_deadcode=128,
                                    uint32_t offset_jmp=0,
                                    bool use_jump=true
                                    );
    static std::vector<uint8_t>  get_code_for_image_base(uint32_t rva);
    static std::vector<uint8_t> trampoline_call(int32_t oep_or_offset);
    static std::vector<uint8_t> trampoline_jmp(int32_t oep_or_offset);
    static uint64_t get_virtual_protect_address(LIEF::PE::Binary& pe);

    static bool is_name_used(const std::string& name, const std::unordered_set<std::string>& used_names);

    static std::vector<std::pair<LIEF::PE::Section*, uint32_t>> rename_section_and_update_permissions(LIEF::PE::Binary& binary);
};


#endif // PEBINARY_MODIFIERS_HPP