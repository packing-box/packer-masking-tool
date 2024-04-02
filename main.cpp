#include <LIEF/LIEF.hpp>
#include <iostream>
#include <vector>


#include "classes/PEBinary.hpp"
#include "classes/PEBinaryAlterations.cpp"



int main( int argc, char **argv) {
    if(argc < 2){
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }

    // =======================================
    // Load the PE file
    PEBinary binary(argv[1]);

    // =======================================
    // apply alterations
    PEBinaryAlterations::add_20_common_api_imports(binary);
    PEBinaryAlterations::add_low_entropy_text_section(binary);
    PEBinaryAlterations::fill_sections_with_zeros(binary);
    PEBinaryAlterations::move_entrypoint_to_new_low_entropy_section(binary);
    PEBinaryAlterations::rename_packer_sections(binary);
    
    
    
    

    // =======================================
    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.patch_imports(true);
    builder.build();
    builder.write("modified_"+std::string(argv[1]));


    return 0;
}