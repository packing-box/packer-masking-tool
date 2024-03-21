#include <LIEF/LIEF.hpp>
#include <iostream>


void add_section(LIEF::PE::Binary& binary, const std::string& name, const std::vector<uint8_t>& data, uint32_t characteristics) {
    LIEF::PE::Section section;
    section.name(name);
    section.characteristics(characteristics);
    section.content(data);
    binary.add_section(section);
}

/*
Usage:
std::vector<uint8_t> section_content = {0x90, 0x90, 0x41};
add_section(*binary.get(), ".nwsc2",section_content, static_cast<uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ));





DWORD AlignSection(_In_ DWORD Size, _In_ DWORD Align, _In_ DWORD Address)
{
	if (!(Size % Align))
		return Address + Size;

	return Address + (Size / Align + 1) * Align;
}
*/