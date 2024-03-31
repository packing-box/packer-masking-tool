
#include "../classes/PEBinary.cpp"
#include "../modifiers/rename_section.cpp"

#include "../utils/select_section_name.cpp"

void _rename_one_packer_section(PEBinary& binary){

    // -- Dictionary of typical section's permissions --
    std::map<std::string, std::string> typical_section_permissions = {
        {".text", "r-x"},
        {".data", "rw-"},
        {".rdata", "r--"},
        {".bss", "rw-"},
        {".tls", "rw-"},
        {".debug", "r--"}
    };

    // -- Get the section names --
    std::vector<std::string> section_names = binary.get_section_names();
    std::vector<std::string> empty_name_sections = binary.get_empty_name_sections();
    std::string entrypoint_section = binary.get_entrypoint_section()->name();
    //std::vector<std::string> real_section_names = binary.get_real_section_names();
    

    // -- Get the common packer/standard section names --
    std::vector<std::string> common_packer_section_names = binary.get_common_packer_section_names();
    std::vector<std::string> standard_section_names = binary.get_standard_section_names();

    // -- Select sections to rename --
    std::vector<std::string> from = {select_section_name({entrypoint_section},{}, common_packer_section_names)};
    from.insert(from.end(), empty_name_sections.begin(), empty_name_sections.end());
    from.insert(from.end(), common_packer_section_names.begin(), common_packer_section_names.end());
    std::string from_section_name = select_section_name(from, {}, section_names);

    // -- Get the permissions of the section --
    std::string from_section_permissions = binary.get_permission_of_section(from_section_name);

    // -- Get the section matching the permissions --
    std::vector<std::string> sections_with_permissions;
    for (const std::pair<std::string, std::string>& section_permission : typical_section_permissions) {
        if (section_permission.second == from_section_permissions) {
            sections_with_permissions.push_back(section_permission.first);
        }
    }
    if(sections_with_permissions.empty()){
        sections_with_permissions = {".text", ".data", ".rdata", ".bss", ".tls", ".debug"};
    }
    // -- Select new names for the sections -- {".text", ".data", ".rdata", ".bss", ".tls", ".debug"}
    std::string to_section_name = select_section_name(sections_with_permissions, standard_section_names,{}, section_names);

    // -- Rename the sections --
    rename_section(binary.get(), from_section_name, to_section_name);
}

void rename_packer_sections(PEBinary& binary){
    try
    {
        for (unsigned int i = 0; i < 50; i++) {
            _rename_one_packer_section(binary);
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "[Error] " << e.what() << '\n';
    }
}


/*

rename_packer_sections:
  attack: evasion
  apply: false
  description: Rename at most 50 section names, starting from the EP section (to be renamed to ".text" if not taken yet) then targetting empty name sections then packer common section names
  fail: stop
  loop: 50
  result:
    PE: rename_section(
            select_section_name(
                [select_section_name(pe['entrypoint_section'], inclusions=COMMON_PACKER_SECTION_NAMES)] +
                    pe['empty_name_sections'] + COMMON_PACKER_SECTION_NAMES,
                inclusions=pe['section_names']
            ),
            select_section_name(
                [".text", ".data", ".rdata", ".bss", ".tls", ".debug"],
                STANDARD_SECTION_NAMES,
                exclusions=pe['section_names']
            )
        )

*/