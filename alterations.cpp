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

void fill_sections_with_zeros(PEBinary& binary){
    // Description: Stretch sections with zeros from their raw size to their virtual size
    size_t size_to_fill = 0;
    for(LIEF::PE::Section& section : binary.get_sections()){
        size_to_fill = section.virtual_size() - section.sizeof_raw_data();
        if(size_to_fill > 0){
            //debug print
            std::cout << "Filling section " << section.name() << " with " << size_to_fill << " zeros" << std::endl;
            binary.append_to_section(section.name(), std::vector<uint8_t>(size_to_fill, 0));
        }else{
            std::cout << "Section " << section.name() << " is already filled (size_to_fill =" << size_to_fill << ")" << std::endl;
        }
    }
}


/*

fill_sections_with_zeros:
  attack: evasion
  description: Stretch sections with zeros from their raw size to their virtual size
  fail: continue
  loop: sections
  result:
    PE: append_to_section(
            section,
            repeatn(randbytes(3), section['virtual_size'] - section['raw_data_size'])
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


    fill_sections_with_zeros(binary);
    
    
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