#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

// for random selection
#include <random>

//#include "modifiers/move_entrypoint_to_slack_space.cpp"
#include "classes/PEBinary.cpp"
#include "modifiers/rename_section.cpp"



std::string select_section_name(const std::vector<std::string>& candidates, 
                                             const std::vector<std::string>& fallback_candidates = {},
                                             const std::vector<std::string>& inclusions = {}, 
                                             const std::vector<std::string>& exclusions = {}) {

    // Include sections if their names are in the 'candidates' and 'inclusions', excluding any in 'exclusions'
    for (const std::string& section_name : candidates) {

        bool  is_in_exclusions = std::find(exclusions.begin(), exclusions.end(), section_name) != exclusions.end();
        bool  is_in_inclusions = std::find(inclusions.begin(), inclusions.end(), section_name) != inclusions.end();
        
        if ( (inclusions.empty() || is_in_inclusions) && (!is_in_exclusions || exclusions.empty())) {
            //result.push_back(section_name);
            return section_name;
        }
    }

    // If the result is empty and there is a fallback list, select randomly from the fallback list
    if ( !fallback_candidates.empty()) {
        // Select a random section name from the fallback candidates
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, fallback_candidates.size()-1);
        return fallback_candidates[dis(gen)];

    }


    return "";
}



// rename_section recieves a LIEF::PE::Binary and two arrays of strings, with the section names and the new names
// for each section. It then renames the sections accordingly.
/*void rename_sections(LIEF::PE::Binary &binary, const std::vector<std::string> &section_names, const std::vector<std::string> &new_names) {
    for (size_t i = 0; i < section_names.size(); ++i) {
        rename_section(binary, section_names[i], new_names[i]);
    }
}



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


void _rename_packer_sections(PEBinary& binary){

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
    std::string section_permissions = binary.get_permission_of_section(from_section_name);

    // -- Get the section matching the permissions --
    std::vector<std::string> sections_with_permissions;
    for (const std::pair<std::string, std::string>& section_permission : typical_section_permissions) {
        if (section_permission.second == section_permissions) {
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



int main( int argc, char **argv) {
    if(argc < 2){
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    // Load your PE file
    //std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(argv[1]);

    // Example usage of select_section_name
    //std::vector<std::string> section_names = select_section_name(*binary.get(), {"text", "data", "rdata", "bss", "tls", "debug"}, {"text", "data", "rdata", "bss", "tls", "debug"});


    // Save the modified PE file
    //LIEF::PE::Builder builder(*binary.get());
    //builder.build();
    //builder.write("modified_"+std::string(argv[1]));

    // =======================================
    

    //PEBinary* binary = new PEBinary(argv[1]);
    //std::vector<std::string> section_names = binary->get_section_names();

    PEBinary binary = PEBinary(argv[1]);
    try
    {
        for (unsigned int i = 0; i < 50; i++) {
            _rename_packer_sections(binary);
        }
    }
    catch(const std::exception& e)
    {
        std::cerr << "[Error] " << e.what() << '\n';
    }
    
    
    // === debug ===
    std::cout << "[AFTER] Section names: " << std::endl;
    for (const std::string& section_name : binary.get_section_names()) {
        std::cout << section_name << std::endl;
    }

    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.build();
    builder.write("modified_"+std::string(argv[1]));


    return 0;
}

// IAT : update_iat()