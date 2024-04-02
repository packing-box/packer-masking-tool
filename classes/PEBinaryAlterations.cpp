#include "PEBinary.hpp"

//#include "../modifiers/rename_section.cpp"
#include "Utilities.cpp"

class PEBinaryAlterations {
public:
    
    static void rename_packer_sections(PEBinary& binary){
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

    static void move_entrypoint_to_new_low_entropy_section(PEBinary& binary){
        // this function is for moving the entry point to a new section with low entropy and common related name

        std::vector<std::string> select_from_this = {".text", ".code", ".init", ".page", ".cde", ".textbss"};
        std::vector<std::string> section_names = binary.get_section_names();
        std::vector<std::string> standard_section_names = binary.get_standard_section_names();

        std::string new_section_name = Utilities::select_section_name(select_from_this, standard_section_names,{}, section_names);

        // from the python version : "randstr(64, randbytes(3), balance=True)", here is the equivalent in C++
        std::vector<uint8_t> post_data = Utilities::generateRandomBytes(64);

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
                binary.append_to_section(section.name(), std::vector<uint8_t>(size_to_fill, 0));
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
        const unsigned int MAX_LOOP = 20;
        // Add common API imports to the IAT, avoiding duplicates
        std::vector<std::pair<std::string, std::string>> COMMON_API_IMPORTS = binary.get_common_api_imports();
        for (unsigned int i = 0; i < MAX_LOOP; i++) {
            binary.add_API_to_IAT(Utilities::select_random(COMMON_API_IMPORTS, binary.get_api_imports()));
        }
    }

private:
    static void _rename_one_packer_section(PEBinary& binary){

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
        std::string from_section_permissions = binary.get_permission_of_section(from_section_name);

        // -- Get the section matching the permissions --
        std::vector<std::string> sections_with_permissions;
        for (const std::pair<const std::string, std::string>& section_permission : typical_section_permissions) {
            if (section_permission.second == from_section_permissions) {
                sections_with_permissions.push_back(section_permission.first);
            }
        }
        if(sections_with_permissions.empty()){
            sections_with_permissions = {".text", ".data", ".rdata", ".bss", ".tls", ".debug"};
        }
        // -- Select new names for the sections -- {".text", ".data", ".rdata", ".bss", ".tls", ".debug"}
        std::string to_section_name = Utilities::select_section_name(sections_with_permissions, standard_section_names,{}, section_names);

        // -- Rename the sections --
        binary.rename_section(from_section_name, to_section_name);
    }
};