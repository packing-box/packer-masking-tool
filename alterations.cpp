#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>
#include <string>

// for randbytes
#include <random>

//#include "modifiers/move_entrypoint_to_slack_space.cpp"
// #include "alterations/rename_packer_sections.cpp"; PEBinary binary = PEBinary(argv[1]); rename_packer_sections(binary);

#include "classes/PEBinary.cpp"
#include "classes/Utilities.cpp"

/*

add_20_common_api_imports:
  attack: evasion
  description: Add common API imports to the IAT, avoiding duplicates
  fail: warn
  loop: 20
  apply: false
  result:
    PE: add_API_to_IAT(
            select(
                random_lst=COMMON_API_IMPORTS,
                exclusions=pe['api_imports']
            )
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
    std::cout << "============================" << std::endl;
    std::cout << "import table: " << std::endl;
    std::vector<std::pair<std::string, std::string>> imports_api = binary.get_api_imports();
    std::cout << "size: " << imports_api.size() << std::endl;
    for(std::pair<std::string, std::string>& import : imports_api){
        std::cout << import.first << " : " << import.second << std::endl;
    }
    std::cout << "============================" << std::endl;


    //add_20_common_api_imports(binary);
    
    
    // === debug ===
    std::cout << "[AFTER] Section EP: " << binary.get_entrypoint_section()->name() << std::endl;

    std::cout << "============================" << std::endl;
    std::cout << "import table: " << std::endl;
    std::vector<std::pair<std::string, std::string>> imports = binary.get_api_imports();
    std::cout << "size: " << imports.size() << std::endl;
    for(std::pair<std::string, std::string>& import : imports){
        std::cout << import.first << " : " << import.second << std::endl;
    }
    std::cout << "============================" << std::endl;

    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.patch_imports(true);
    builder.build();
    builder.write("modified_"+std::string(argv[1]));


    return 0;
}

// IAT : update_iat()