#include "LIEF/PE.hpp"
#include <iostream>
#include "pe_def.cpp"




void add_section_test(std::string file_in, std::string file_out="new_binary.exe") {
    PEFile pe_file(file_in);
    std::string data_section = "This is a new section";
    //std::vector<uint8_t> data(0x1000, 0x41);
    std::vector<uint8_t> data_section_bytes(data_section.begin(), data_section.end());
    pe_file.add_section(".new", data_section_bytes, static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ));
    pe_file.write(file_out,true, true);
}

void change_section_name_test(std::string file_in, std::string file_out="new_binary.exe") {
    PEFile pe_file(file_in);
    pe_file.change_section_name(".text", ".newtxt");
    pe_file.write(file_out,true, true);
}


void show_sections(PEFile& pe_file) {
    std::cout << "Sections:" << std::endl;
    for (PESection section : pe_file.get_sections()) {
        std::cout << section.name() << " : " << (section.is_executable()? "x" : " ") << (section.is_readable()? "r" : " ") << (section.is_writable()? "w" : " ") << std::endl;
    }
}

void show_imports(PEFile& pe_file) {
    // count imports
    size_t count = 0;
    std::cout << "Imports:" << std::endl;
    for (std::string import : pe_file.api_imports()) {
        std::cout << import << std::endl;
        count++;
    }
    if (count == 0) {
        std::cout << "No imports" << std::endl;
    }else{
        std::cout << "Total imports: " << count << std::endl;
    }
}



int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }

    const std::string binary = argv[1];
    PEFile pe_file(binary);
    std::cout << "Entrypoint: " << std::hex << pe_file.entrypoint() << std::endl;
    // show secions
    show_sections(pe_file);
    show_imports(pe_file);

    // add a new import
    pe_file.add_import("USER32.dll", "CharLowerA");
    //pe_file.add_import("NTDLL.dll", "NtCreateFile");
    pe_file.write("new_binary.exe",false, true);





    // open the new binary
    PEFile new_pe_file("new_binary.exe");
    std::cout << "Entrypoint: " << std::hex << new_pe_file.entrypoint() << std::endl;
    // show secions
    //show_sections(new_pe_file);
    show_imports(new_pe_file);

  return 0;
}