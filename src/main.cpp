#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>


#include "classes/PEBinary.hpp"
#include "classes/PEBinaryAlterations.cpp"

#define ITALIC "\033[3m"
#define RESET "\033[0m"
// colors
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define GRAY "\033[90m"

void header(){
    // Logo art
    std::cout << R"(    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               

)";
    // author, copy right, version
    std::cout << GRAY << ITALIC << " Author       :   J. RAMHANI" << std::endl;
    std::cout <<  " Contributor  :   A. D'Hondt" << std::endl;
    std::cout <<  " Version      :   0.1" << std::endl;
    std::cout <<  " Copyright    :   © 2024" << std::endl;
    std::cout <<  " License      :   GNU General Public License v3.0" << std::endl;
    std::cout << GRAY << "======================================================" << RESET << std::endl;
    std::cout << std::endl;
}

void help(const char* program_name){
    
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
    std::cerr << "Other options: (by default all of them applies)" << std::endl;
    std::cerr << "    --add-api         : Add 20 common API imports to the PE file." << std::endl;
    //std::cerr << "    --low-entropy     : Add a low entropy text section to the PE file." << std::endl;
    //std::cerr << "    --fill-zero       : Fill sections with zeros from their raw size to their virtual size." << std::endl;
    std::cerr << "    --move-ep         : Move the entry point to a new low entropy section." << std::endl;
    std::cerr << "    --rename-sections : Rename packer sections to standard section names." << std::endl;
    
    std::cerr << "    --permissions      : Update the permissions of all sections to standard ones (rwx/rw-/..) and move the entry point to a new section." << std::endl;

    std::cerr << std::endl;
}


int main( int argc, char **argv) {
    header();
    if(argc < 2){
        help(argv[0]);
        return 1;
    }

    for(int i = 0; i < argc; i++){
        if (std::strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            return 1;
        }
    }

    // intialize output file name
    std::string output_file_name = "output_"+std::string(argv[1]);

    // =======================================
    // Load the PE file
    PEBinary binary(argv[1]);

    // =======================================
    bool at_least_one_alteration = false;
    for(int i = 0; i < argc; i++){
        if (std::strcmp(argv[i], "-o") == 0)
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
        } 
        /*else if (std::strcmp(argv[i], "--fill-zero") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::fill_sections_with_zeros(binary);
        } */
        else if (std::strcmp(argv[i], "--move-ep") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);
        } else if (std::strcmp(argv[i], "--rename-sections") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::rename_packer_sections(binary);
        }
        else if (std::strcmp(argv[i], "--permissions") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::update_section_permissions_and_move_ep(binary);
        }
        
    }

    if(!at_least_one_alteration){
        // ==== apply all alterations ======
        //PEBinaryAlterations::add_20_common_api_imports(binary); // TODO: fix (keep API common)
        //PEBinaryAlterations::add_low_entropy_text_section(binary);
        //PEBinaryAlterations::fill_sections_with_zeros(binary);
        //PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);
        //PEBinaryAlterations::rename_packer_sections(binary);

        PEBinaryAlterations::update_section_permissions_and_move_ep(binary);
    }
    
    
    
    
    

    // =======================================
    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.patch_imports(true);
    builder.build();
    builder.write(output_file_name);
    // green color
    std::cout << "\033[32m" << "[SUCCESS] \033[0m File saved as: " << output_file_name << std::endl;

    return 0;
}