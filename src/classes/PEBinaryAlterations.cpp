#include "PEBinary.hpp"

//#include "../modifiers/rename_section.cpp"
#include "Utilities.cpp"
// random number generator
#include <random>
#include "RawSizeEditor.hpp"
#include "constants.hpp"
#include <algorithm>

class PEBinaryAlterations {
public:

    PEBinaryAlterations(PEBinary& binary) : binary(binary) {}

    void set_verbose(bool verbose){
        this->verbose = verbose;
    }

    void set_binary(PEBinary&& binary){
        this->binary = std::move(binary);
    }

    PEBinary& get_binary(){
        return binary;
    }

    void build_and_write(std::string output_file_name, bool& edited_iat){
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
    
     void rename_packer_sections(){
        try
        {
            if(verbose){
                std::cout << std::endl<< YELLOW << "[INFO]  \033[0m Renaming packer sections to standard section names..." << RESET << std::endl;
            }

            for (unsigned int i = 0; i < 50; i++) {
                _rename_one_packer_section();
            }
        }
        catch(const std::exception& e)
        {
            if(verbose){
                std::cerr << "[Error] " << e.what() << '\n';
            }
        }
    }

     void update_section_permissions_and_move_ep(){
        try
        {
            if(verbose){
                std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Updating the permissions of all sections to standard ones (rwx/rw-/..), moving the entry point to a new section and Renaming sections to standard ones..." << RESET << std::endl;
            }
            // get file size
            size_t file_size = binary.get_size();

            // -- Update the permissions of the sections --
            //std::vector<uint8_t> pre_data = Utilities::generateRandomBytes(64);
            // between 10% and 20% of the file size
            // max between five_percent and 2048 and max between ten_percent and 8192
            size_t lower_bound = std::max(static_cast<size_t>(file_size * 10 / 100), static_cast<size_t>(2048));
            size_t higher_bound = std::max(static_cast<size_t>(file_size * 20 / 100), static_cast<size_t>(8192));
            size_t random_nb_bytes = Utilities::get_random_number(lower_bound, higher_bound);
            //std::vector<uint8_t> post_data = Utilities::generateRandomBytes(random_nb_bytes);

            std::vector<uint8_t> post_data;
            std::vector<uint8_t> randbytes = Utilities::generateRandomBytes(3);
            for(size_t i = 0; i < random_nb_bytes; i++){
                post_data.push_back(randbytes[i % 3]);
            }

            std::vector<uint8_t> pre_data;
            std::vector<uint8_t> randbytes2 = Utilities::generateRandomBytes(3);
            for(size_t i = 0; i < random_nb_bytes; i++){
                pre_data.push_back(randbytes2[i % 3]);
            }

            size_t nb_deadcode = Utilities::get_random_number(256, 512);
            // generate random number between
            // TODO: first check if the permissions are already set correctly
            binary.update_section_permissions(pre_data, post_data, nb_deadcode);
        }
        catch(const std::exception& e)
        {
            if(verbose){
                std::cerr << RED <<"[Error] \033[0m" << e.what() << '\n';
            }
        }
    }


     void edit_raw_size_of_sections_in_header(){
        if(verbose){
            std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Editing the raw size value in the header of sections having a 0 raw size (without adding real data bytes)..." << RESET << std::endl;
        }
        // Description: Edit the raw size of sections in the header
        std::string file_path = binary.get_filename();

        RawSizeEditor editor(file_path.c_str());
        size_t total_added_raw_size = editor.edit(0.9, true);
        if(total_added_raw_size > 0){
            //std::cout << "Total added raw size: " << total_added_raw_size << std::endl;
        }else{
            if(verbose){
                std::cerr << "No raw size added" << std::endl;
            }
        }
    }

     void move_entrypoint_to_new_low_entropy_section(){
        // this function is for moving the entry point to a new section with low entropy and common related name
        if(verbose){
            std::cout << std::endl<<YELLOW << "[INFO]  \033[0m Moving the entry point to a new low entropy section..." << RESET << std::endl;
        }
        std::vector<std::string> select_from_this = {".text", ".code", ".init", ".page", ".cde", ".textbss"};
        std::vector<std::string> section_names = binary.get_section_names();
        std::vector<std::string> standard_section_names = binary.get_standard_section_names();

        std::string new_section_name = Utilities::select_section_name(select_from_this, standard_section_names,{}, section_names);

        // from the python version : "randstr(64, randbytes(3), balance=True)", here is the equivalent in C++
        //std::vector<uint8_t> post_data = Utilities::generateRandomBytes(64);
        std::vector<uint8_t> post_data;
        std::vector<uint8_t> randbytes = Utilities::generateRandomBytes(3);
        for(size_t i = 0; i < 64; i++){
            post_data.push_back(randbytes[i % 3]);
        }// this for loop is the repeatn function in python

        // move the entry point to the new section
        binary.move_entrypoint_to_new_section(new_section_name, 0, {}, post_data);
        // NOTE:
        // Characteristics = 0 will be replaced with READ | EXECUTE
        // pre_data = {}  : empty
    }

     void fill_sections_with_zeros(){
        // Description: Stretch sections with zeros from their raw size to their virtual size
        size_t size_to_fill = 0; // its unsigned !!
        if(verbose){
            std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Filling sections with zeros from their raw size to their virtual size..." << RESET << std::endl;
        }
        for(LIEF::PE::Section& section : binary.get_sections()){
            size_to_fill = section.virtual_size() - section.sizeof_raw_data();
            if(size_to_fill > 0 && section.virtual_size() > section.sizeof_raw_data()){
                std::vector<uint8_t> data_fill = Utilities::generateRandomBytes(3);
                std::vector<uint8_t> data(size_to_fill);
                for(size_t i = 0; i < size_to_fill; i++){
                    data.push_back(data_fill[i % 3]);
                }
                binary.append_to_section(section.name(), data);
            }
        }
        // std::cerr << RED << "[WARNING] \033[0m Currently filling sections with zeros does NOT ALWAYS maintain the executable functionality..." << RESET << std::endl;
    }

     void add_low_entropy_text_section(){
        // description: Add a code section with low entropy and common related name (in last resort, use a random common name, whatever the typical section type)
        std::vector<std::string> select_from_this = {".text", ".code", ".init", ".page", ".cde", ".textbss"};
        std::vector<std::string> section_names = binary.get_section_names();
        std::vector<std::string> standard_section_names = binary.get_standard_section_names();

        std::string new_section_name = Utilities::select_section_name(select_from_this, standard_section_names,{}, section_names);
        // replicate repeatn(randbytes(3), size(pe, .1, pe['optional_header']['file_alignment']))
        std::vector<uint8_t> data;
        std::vector<uint8_t> randbytes = Utilities::generateRandomBytes(3);
        size_t file_alignment = binary.get_optional_header().file_alignment();
        size_t size = binary.calculate_size(0.1, file_alignment);
        for(size_t i = 0; i < size; i++){
            data.push_back(randbytes[i % 3]);
        }// this for loop is the repeatn function in python
        
        binary.add_section(new_section_name,data, 0, LIEF::PE::PE_SECTION_TYPES::TEXT);
    }

     void add_20_common_api_imports(){
        // Description: Add 20 common API imports to the PE file
        // WARNING: Currently adding API imports does not maintain the executable functionality
        if(verbose){
            std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Adding 20 common API imports to the PE file..." << RESET << std::endl;
        }
        const unsigned int MAX_LOOP = 20;
        // Add common API imports to the IAT, avoiding duplicates
        std::vector<std::pair<std::string, std::string>> COMMON_API_IMPORTS = binary.get_common_api_imports();
        std::vector<std::pair<std::string, std::string>> api_imports = binary.get_api_imports();

        // select 20 random common API imports before 
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, COMMON_API_IMPORTS.size()-1);

        for (unsigned int i = 0; i < MAX_LOOP; i++) {
            // select a random common API import (no duplicates)
            std::pair<std::string, std::string> random_api_import = COMMON_API_IMPORTS[dis(gen)];
            // debug print
            if(std::find(api_imports.begin(), api_imports.end(), random_api_import) == api_imports.end()){
                // std::cout << "[-]   Adding API import: " << random_api_import.first << " - " << random_api_import.second << std::endl;

                binary.add_API_to_IAT(random_api_import);
                // add the API import to the list of imports
                api_imports.push_back(random_api_import);
            }
        }

        if(verbose){
            std::cout << RED << "[WARNING] \033[0m Currently adding API imports does not maintain the executable functionality..." << RESET << std::endl;
        }
    }

private:
    PEBinary& binary;
    bool verbose = false;
     void _rename_one_packer_section(){

        // -- Get the section names --
        std::vector<std::string> section_names = binary.get_section_names();
        std::vector<std::string> empty_name_sections = binary.get_empty_name_sections();
        std::string entrypoint_section = binary.get_entrypoint_section()->name();
        //std::vector<std::string> real_section_names = binary.get_real_section_names();
        

        // -- Get the common packer/standard section names --
        std::vector<std::string> common_packer_section_names = binary.get_common_packer_section_names();
        std::vector<std::string> standard_section_names = binary.get_standard_section_names();

        // -- Select sections to rename --
        std::vector<std::string> from = {Utilities::select_section_name({entrypoint_section},{}, common_packer_section_names)};
        from.insert(from.end(), empty_name_sections.begin(), empty_name_sections.end());
        from.insert(from.end(), common_packer_section_names.begin(), common_packer_section_names.end());
        std::string from_section_name = Utilities::select_section_name(from, {}, section_names);

        // -- Abort if from_section_name is empty --
        if (from_section_name.empty()) {
            // this can happen if no common packer section is found
            return;
        }

        // -- Get the permissions of the section --
        //std::string from_section_permissions = binary.get_permission_of_section(from_section_name);

        // -- Get the section matching the permissions --
        // -- Select new names for the sections -- {".text", ".data", ".rdata", ".bss", ".tls", ".debug"}
        std::string to_section_name = Utilities::select_section_name({".text", ".data", ".rdata", ".bss", ".tls", ".debug"}, standard_section_names,{}, section_names);

        // -- Rename the sections --
        binary.rename_section(from_section_name, to_section_name);
    }
};