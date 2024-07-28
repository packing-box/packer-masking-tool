#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>

#include "classes/PEBinary.hpp"
#include "classes/PEBinaryAlterations.cpp"

#include "classes/constants.hpp"

void header(){
    // Logo art
    std::cout << R"(    _   __      __  ____             __            __          
   / | / ____  / /_/ __ \____ ______/ /_____  ____/ / __    __ 
  /  |/ / __ \/ __/ /_/ / __ `/ ___/ //_/ _ \/ __  __/ /___/ /_
 / /|  / /_/ / /_/ ____/ /_/ / /__/ ,< /  __/ /_/ /_  __/_  __/
/_/ |_/\____/\__/_/    \__,_/\___/_/|_|\___/\__,_/ /_/   /_/   
                                                               

)";
    // author, copy right, version
    std::cout << GRAY << ITALIC 
                <<  " Authors      :   Jaber RAMHANI, Alexandre D'Hondt" << std::endl;
    //std::cout   <<  " Contributor  :   A. D'Hondt" << std::endl;
    std::cout   <<  " Version      :   0.1" << std::endl;
    std::cout   <<  " Copyright    :   © 2021-2024 Alexandre D'Hondt, Jaber Ramhani" << std::endl;
    std::cout   <<  " License      :   GNU General Public License v3.0" << std::endl;
    std::cout << GRAY << "======================================================" << RESET << std::endl;
    std::cout << std::endl;
}

void help(const char* program_name){
    
    // Description
    std::cerr << "Description: This program applies some alterations to a PE file. \n Note that when no alteration is specified ALL of them will be applied, if at least one is specified only selected ones will be applied" << std::endl;
    std::cerr << std::endl;
    // Usage
    std::cerr << "Usage: " << program_name << " <input_file> [OPTIONS]" << std::endl;

    std::cerr << std::endl;
    std::cerr << "    -o <output_file>  : Set the output file name. (default:<input_file>_out.exe)" << std::endl;
    std::cerr << "    --help            : Display this help message." << std::endl;
    std::cerr << std::endl;

    // possible options
    std::cerr << "Other options: (by default the behavior is --permissions --raw-size)" << std::endl;
    std::cerr << "    --add-api         : Add 20 common API imports to the PE file. (Rebuilding a functional file not working yet)" << std::endl;
    //std::cerr << "    --fill-sections       : Fill sections with zeros from their raw size to their virtual size." << std::endl;
    std::cerr << "    --move-ep         : Move the entry point to a new low entropy section." << std::endl;
    std::cerr << "    --rename-sections : Rename packer sections to standard section names." << std::endl;
    
    std::cerr << "    --permissions      : Update the permissions of all sections to standard ones (rwx/rw-/..), moves the EP to a new section and renames sections." << std::endl;

    std::cerr << "    --raw-size    : Edit the raw size value in the header of sections having a 0 raw size (without adding real data bytes)." << std::endl;

    std::cerr << std::endl;
}


void build_and_write(PEBinary& binary, std::string output_file_name, bool& edited_iat){
    LIEF::PE::Builder builder(*binary.get());
    builder.build_overlay(true);

    if(edited_iat){
        builder.patch_imports(true);
        builder.build_imports(true); // This adds .l1 section (and breaks the executable)
        edited_iat = false;
    }
    
    builder.build();
    builder.write(output_file_name);
}


int main( int argc, char **argv) {
    header();
    std::string input;

    if(argc < 2){
        help(argv[0]);
        return 1;
    }

    input = std::string(argv[1]);

    for(int i = 0; i < argc; i++){
        if (std::strcmp(argv[i], "--help") == 0) {
            help(argv[0]);
            return 1;
        }
    }

    // intialize output file name
    std::string output_file_name = std::string(input);
    // remove the extension
    output_file_name = output_file_name.substr(0, output_file_name.find_last_of("."));
    output_file_name += "_out.exe";

    // =======================================
    // Load the PE file

    PEBinary binary(input);

    // =======================================
    bool edited_iat = false;
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
            edited_iat = true;
            build_and_write(binary, output_file_name, edited_iat);

            binary = PEBinary(output_file_name);
            
        } 
        else if (std::strcmp(argv[i], "--fill-sections") == 0)
        {
            at_least_one_alteration = true;
            PEBinaryAlterations::fill_sections_with_zeros(binary);
        }
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
        else if (std::strcmp(argv[i], "--raw-size") == 0)
        {
            at_least_one_alteration = true;
            build_and_write(binary, output_file_name, edited_iat);

            binary = PEBinary(output_file_name);

            PEBinaryAlterations::edit_raw_size_of_sections_in_header(binary);

            binary = PEBinary(output_file_name);

        }
        
    }

    if(!at_least_one_alteration){
        // ==== apply all alterations ======
        
        //PEBinaryAlterations::add_low_entropy_text_section(binary);
        //PEBinaryAlterations::fill_sections_with_zeros(binary);
        //PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);

        // TODO:
        //PEBinaryAlterations::add_20_common_api_imports(binary); // TODO: fix (keep API common)
        // ___ this adds a section .l1 or .l2 (because of lief) ... so need to rename ___
        //PEBinaryAlterations::rename_packer_sections(binary);
        

        // It moves the entry point to a new section and updates the permissions of all sections
        // And also renames the packer sections to standard section names
        
        PEBinaryAlterations::update_section_permissions_and_move_ep(binary);

        build_and_write(binary, output_file_name, edited_iat);

        binary = PEBinary(output_file_name);

        PEBinaryAlterations::edit_raw_size_of_sections_in_header(binary);

        //binary = PEBinary(output_file_name);
        std::cout << std::endl <<  GREEN << "[SUCCESS] \033[0m File saved as: " << output_file_name << RESET << std::endl;
        return 0;
    }
    
    
    
    
    

    // =======================================
    // Save the modified PE file
    build_and_write(binary, output_file_name, edited_iat);

    std::cout << std::endl <<  GREEN << "[SUCCESS] \033[0m File saved as: " << output_file_name << RESET << std::endl;

    return 0;
}