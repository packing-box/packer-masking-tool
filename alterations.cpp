#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>
#include <string>

// for randbytes
#include <random>

//#include "modifiers/move_entrypoint_to_slack_space.cpp"
// #include "alterations/rename_packer_sections.cpp"; PEBinary binary = PEBinary(argv[1]); rename_packer_sections(binary);

#include "classes/PEBinary.cpp"
#include "utils/select_section_name.cpp"
#include "utils/generate_random_bytes.cpp"

void move_entrypoint_to_new_low_entropy_section(PEBinary& binary){
    // this function is for moving the entry point to a new section with low entropy and common related name

    std::vector<std::string> select_from_this = {".text", ".code", ".init", ".page", ".cde", ".textbss"};
    std::vector<std::string> section_names = binary.get_section_names();
    std::vector<std::string> standard_section_names = binary.get_standard_section_names();

    std::string to_section = select_section_name(select_from_this, standard_section_names,{}, section_names);

    // from the python version : "randstr(64, randbytes(3), balance=True)", here is the equivalent in C++
    std::vector<uint8_t> post_data = generateRandomBytes(64);

    // move the entry point to the new section
    binary.move_entrypoint_to_new_section(to_section, 0, {}, post_data);
    // NOTE:
    // Characteristics = 0 will be replaced with READ | EXECUTE
    // pre_data = {}  : empty
}


/*

move_entrypoint_to_new_low_entropy_section:
  attack: evasion
  comment: Currently, this alteration is not resistant to further signature creation (i.e. trampoline code is static and it is trivial to generate a signature for detecting it) ; this could be refined with adding randomization so that bytes after EP cannot be used for signatures without causing many FP.
  description: Move the Entry Point to a new section with low entropy and common related name (in last resort, use a random common name, whatever the typical section type)
  result:
    PE: move_entrypoint_to_new_section(
            select_section_name(
                [".text", ".code", ".init", ".page", ".cde", ".textbss"],
                STANDARD_SECTION_NAMES,
                exclusions=pe['section_names']
            ),
            post_data=randstr(64, randbytes(3), balance=True)
        )
*/




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
    
    PEBinary binary(argv[1]);

    std::cout << "[BEFORE] Section EP: " << binary.get_entrypoint_section()->name() << std::endl;

    // === debug ===
    std::cout << "Section names: " << std::endl;
    for(auto& section_name : binary.get_section_names()){
        std::cout << section_name  << " : " << binary.get_permission_of_section(section_name) << std::endl;
    }


    move_entrypoint_to_new_low_entropy_section(binary);
    
    
    // === debug ===
    std::cout << "[AFTER] Section EP: " << binary.get_entrypoint_section()->name() << std::endl;

    std::cout << "Section names: " << std::endl;
    for(auto& section_name : binary.get_section_names()){
        std::cout << section_name  << " : " << binary.get_permission_of_section(section_name) << std::endl;
    }

    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.build();
    builder.write("modified_"+std::string(argv[1]));


    return 0;
}

// IAT : update_iat()