#include <LIEF/LIEF.hpp>
#include <vector>
#include <random>
#include <iostream>


// Helper function to add dummy instructions
std::vector<uint8_t> get_dummy_instructions(size_t count) {
    // Define an array of dummy instructions (equivalent to the ones in your Python example)
    const std::vector<std::vector<uint8_t>> dummy_instructions = {
        {0x90}, // NOP
        {0x87, 0xC0}, // XCHG EAX, EAX
        {0x83, 0xC0, 0x00}, // ADD EAX, 0
        {0x83, 0xE9, 0x00}, // SUB ECX, 0
        {0x89, 0xC2}, // MOV EDX, EDX
        {0x50, 0x58}, // PUSH EAX + POP EAX
        {0x8D, 0x1B}, // LEA EBX, [EBX]
        {0x81, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x81, 0xEF, 0x01, 0x00, 0x00, 0x00}, // ADD EDI, 1 + SUB EDI, 1
        {0x81, 0xE6, 0xFF, 0xFF, 0xFF, 0xFF}, // AND ESI, 0xFFFFFFFF
        {0x83, 0xCA, 0x00}, // OR EDX, 0
        {0xEB, 0x00}, // JMP SHORT $+2
        {0x33, 0xC0}, // XOR EAX, EAX
        {0x33, 0xC9}, // XOR ECX, ECX
        {0x33, 0xD2}, // XOR EDX, EDX
        {0x33, 0xDB}, // XOR EBX, EBX
        {0xD1, 0xC0}, // ROL EAX, 1
        {0x50, 0x58}, // PUSH EAX + POP EAX
        {0x05, 0x01, 0x00, 0x00, 0x00, 0x2D, 0x01, 0x00, 0x00, 0x00}, // ADD EAX, 1 + SUB EAX, 1
        {0xF9, 0xF8}, // STC + CLC
        {0x89, 0xC1, 0x89, 0xC8}, // MOV ECX, EAX + MOV EAX, ECX
        {0x8D, 0x80, 0x00, 0x00, 0x00, 0x00}, // LEA EAX, [EAX]
        {0x83, 0xC8, 0x00}, // OR EAX, 0
        {0xEB, 0x00, 0x90}, // JMP SHORT 2 bytes over NOP
        {0x50, 0x48, 0x89, 0xC1, 0x40, 0x58}, // PUSH EAX + DEC EAX + MOV ECX, EAX + INC EAX + POP EAX
    }; // 25 dummy instructions

    std::vector<uint8_t> instructions;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, dummy_instructions.size() - 1);

    for (size_t i = 0; i < count; ++i) {
        auto& selected = dummy_instructions[distr(gen)];
        instructions.insert(instructions.end(), selected.begin(), selected.end());
    }

    return instructions;
}


std::vector<uint8_t> get_trampoline_instructions(uint64_t original_entrypoint, size_t nb_pre_instructions=5, size_t nb_mid_instructions=5, bool is_64bits) {
    std::vector<uint8_t> trampoline;
    trampoline.reserve(32); // Reserve some space to avoid frequent reallocations

    // Add dummy instructions at the beginning
    std::vector<uint8_t> pre_instructions = get_dummy_instructions(nb_pre_instructions);
    trampoline.insert(trampoline.end(), pre_instructions.begin(), pre_instructions.end());


    // Trampoline logic to jump back to the original entry point
    if (is_64bits) {
        trampoline.insert(trampoline.end(), {0x48, 0xB8}); // MOV RAX, <addr>
        for (int i = 0; i < 8; ++i) {
            trampoline.push_back((original_entrypoint >> (i*8)) & 0xFF); // the address of the original entry point
        }
        trampoline.insert(trampoline.end(), {0x50}); // PUSH RAX
    } else {
        trampoline.push_back(0x68); // PUSH <addr>
        // in little endian
        for (int i = 0; i < 4; ++i) {
            trampoline.push_back((original_entrypoint >> (i*8)) & 0xFF); // the address of the original entry point
        }
    }

    // Add dummy instructions in the middle
    std::vector<uint8_t> mid_instructions = get_dummy_instructions(nb_mid_instructions);
    trampoline.insert(trampoline.end(), mid_instructions.begin(), mid_instructions.end());

    // Add the RET instruction
    trampoline.push_back(0xC3); // RET


    return trampoline;
}


// Function to move the entry point to a new section
void move_entrypoint_to_new_section(LIEF::PE::Binary& binary, const std::string& name, uint32_t characteristics,
                                    size_t nb_pre_instructions, size_t nb_mid_instructions,
                                    const std::vector<uint8_t>& pre_data, const std::vector<uint8_t>& post_data) {
    auto& optional_header = binary.optional_header();
    uint64_t original_entrypoint = optional_header.addressof_entrypoint() + optional_header.imagebase();

    bool is_64bits = binary.optional_header().magic() == LIEF::PE::PE_TYPE::PE32_PLUS;

    std::vector<uint8_t> entrypoint_data = get_trampoline_instructions(original_entrypoint, nb_pre_instructions, nb_mid_instructions ,is_64bits);

    // Combine pre_data, trampoline, and post_data
    std::vector<uint8_t> section_data = pre_data;
    section_data.insert(section_data.end(), entrypoint_data.begin(), entrypoint_data.end());
    section_data.insert(section_data.end(), post_data.begin(), post_data.end());

    // Create and add the new section
    LIEF::PE::Section new_section;
    new_section.name(name);
    new_section.characteristics(characteristics);
    new_section.content(section_data);
    binary.add_section(new_section);

    // Update the entry point to point to the new section (pre_data + trampoline + post_data)
    optional_header.addressof_entrypoint(binary.get_section(name)->virtual_address() + pre_data.size());
}


int _main( int argc, char **argv) {
    if(argc < 2){
        std::cerr << "Usage: " << argv[0] << " <input_file>" << std::endl;
        return 1;
    }
    // Load your PE file
    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(argv[1]);

    // Example usage of move_entrypoint_to_new_section
    move_entrypoint_to_new_section(*binary, ".nwsec", static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE | LIEF::PE::Section::CHARACTERISTICS::MEM_READ), 5, 5, {}, {});

    // Save the modified PE file
    LIEF::PE::Builder builder(*binary.get());
    builder.build();
    builder.write("modified_"+std::string(argv[1]));

    return 0;
}