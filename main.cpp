#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>


#include "classes/PEBinary.hpp"
#include "classes/PEBinaryAlterations.cpp"


void help(const char* program_name){
    // Logo art

std::cerr << R"(    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               

)";

    // Description
    std::cerr << "Description: This program applies some alterations to a PE file. \n Note that when no alteration is specified ALL of them will be applied, if at least one is specified only selected ones will be applied" << std::endl;
    std::cerr << std::endl;
    // Usage
    std::cerr << "Usage: " << program_name << " <input_file>" << std::endl;

    std::cerr << std::endl;
    std::cerr << "    -o <output_file>  : Set the output file name." << std::endl;
    std::cerr << "    --help            : Display this help message." << std::endl;
    std::cerr << std::endl;

    // possible options
    std::cerr << "Other options:" << std::endl;
    std::cerr << "    --add-api         : Add 20 common API imports to the PE file." << std::endl;
    std::cerr << "    --low-entropy     : Add a low entropy text section to the PE file." << std::endl;
    std::cerr << "    --fill-zero       : Fill sections with zeros from their raw size to their virtual size." << std::endl;
    std::cerr << "    --move-ep         : Move the entry point to a new low entropy section." << std::endl;
    std::cerr << "    --rename-packer   : Rename packer sections." << std::endl;
    std::cerr << std::endl;
}


int main( int argc, char **argv) {
    if(argc < 2){
        help(argv[0]);
        return 1;
    }

    // intialize output file name
    std::string output_file_name = "output_"+std::string(argv[1]);

    // =======================================
    // Load the PE file
    PEBinary binary(argv[1]);

    // =======================================
    bool at_least_one_alteration = false;
    for(int i = 0; i < argc; i++){
        if (std::strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            return 1;
        } else if (std::strcmp(argv[i], "-o") == 0)
        {
            if(i+1 < argc){
                output_file_name = std::string(argv[i+1]);
            }
        }
        // ===== Alterations =====
        else if (std::strcmp(argv[i], "--add-api") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::add_20_common_api_imports(binary);
        } else if (std::strcmp(argv[i], "--low-entropy") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::add_low_entropy_text_section(binary);
        } else if (std::strcmp(argv[i], "--fill-zero") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::fill_sections_with_zeros(binary);
        } else if (std::strcmp(argv[i], "--move-ep") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);
        } else if (std::strcmp(argv[i], "--rename-packer") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::rename_packer_sections(binary);
        }
        
    }

    if(!at_least_one_alteration){
        // ==== apply all alterations ======
        //PEBinaryAlterations::add_20_common_api_imports(binary);
        PEBinaryAlterations::add_low_entropy_text_section(binary);
        //PEBinaryAlterations::fill_sections_with_zeros(binary);
        PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);
        PEBinaryAlterations::rename_packer_sections(binary);
    }
    
    
    
    
    

    // =======================================
    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.patch_imports(true);
    builder.build();
    builder.write(output_file_name);


    return 0;
}