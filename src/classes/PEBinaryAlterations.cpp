#include "PEBinary.hpp"

//#include "../modifiers/rename_section.cpp"
#include "Utilities.cpp"
// random number generator
#include <random>
#include "RawSizeEditor.cpp"
#include "constants.hpp"

class PEBinaryAlterations {
public:
    
    static void rename_packer_sections(PEBinary& binary){
        try
        {
            std::cout << std::endl<< YELLOW << "[INFO]  \033[0m Renaming packer sections to standard section names..." << RESET << std::endl;

            for (unsigned int i = 0; i < 50; i++) {
                _rename_one_packer_section(binary);
            }
        }
        catch(const std::exception& e)
        {
            std::cerr << "[Error] " << e.what() << '\n';
        }
    }

    static void update_section_permissions_and_move_ep(PEBinary& binary){
        try
        {
            std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Updating the permissions of all sections to standard ones (rwx/rw-/..), moving the entry point to a new section and Renaming sections to standard ones..." << RESET << std::endl;

            // -- Update the permissions of the sections --
            //std::vector<uint8_t> pre_data = Utilities::generateRandomBytes(64);
            size_t random_nb_bytes = Utilities::get_random_number(64, 4096);
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

            size_t nb_deadcode = Utilities::get_random_number(2, 64);
            // generate random number between
            // TODO: first check if the permissions are already set correctly
            binary.update_section_permissions(pre_data, post_data, nb_deadcode);
        }
        catch(const std::exception& e)
        {
            std::cerr << RED <<"[Error] \033[0m" << e.what() << '\n';
        }
    }


    static void edit_raw_size_of_sections_in_header(PEBinary& binary){
        std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Editing the raw size value in the header of sections having a 0 raw size (without adding real data bytes)..." << RESET << std::endl;

        // Description: Edit the raw size of sections in the header
        std::string file_path = binary.get_filename();

        RawSizeEditor editor(file_path.c_str());
        size_t total_added_raw_size = editor.edit(0.9, true);
        if(total_added_raw_size > 0){
            //std::cout << "Total added raw size: " << total_added_raw_size << std::endl;
        }else{
            std::cerr << "No raw size added" << std::endl;
        }
    }

    static void move_entrypoint_to_new_low_entropy_section(PEBinary& binary){
        // this function is for moving the entry point to a new section with low entropy and common related name
        std::cout << std::endl<<YELLOW << "[INFO]  \033[0m Moving the entry point to a new low entropy section..." << RESET << std::endl;

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

    static void fill_sections_with_zeros(PEBinary& binary){
        // Description: Stretch sections with zeros from their raw size to their virtual size
        size_t size_to_fill = 0;
        for(LIEF::PE::Section& section : binary.get_sections()){
            size_to_fill = section.virtual_size() - section.sizeof_raw_data();
            if(size_to_fill > 0){
                std::vector<uint8_t> data_fill = Utilities::generateRandomBytes(3);
                std::vector<uint8_t> data(size_to_fill);
                for(size_t i = 0; i < size_to_fill; i++){
                    data.push_back(data_fill[i % 3]);
                }
                binary.append_to_section(section.name(), data);
            }
        }
    }

    static void add_low_entropy_text_section(PEBinary& binary){
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

    static void add_20_common_api_imports(PEBinary& binary){
        std::cout <<std::endl<< YELLOW << "[INFO]  \033[0m Adding 20 common API imports to the PE file..." << RESET << std::endl;

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

        std::cout << RED << "[WARNING] \033[0m Currently adding API imports does not maintain the executable functionality..." << RESET << std::endl;

    }

private:
    static void _rename_one_packer_section(PEBinary& binary){

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