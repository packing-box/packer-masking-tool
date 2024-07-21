std::string select_section_name(const std::vector<std::string>& candidates, 
                                             const std::vector<std::string>& fallback_candidates = {},
                                             const std::vector<std::string>& inclusions = {}, 
                                             const std::vector<std::string>& exclusions = {}) {
    std::vector<std::string> result;

    // Include sections if their names are in the 'candidates' and 'inclusions', excluding any in 'exclusions'
    for (const std::string& section_name : candidates) {

        bool  is_in_exclusions = std::find(exclusions.begin(), exclusions.end(), section_name) != exclusions.end();
        bool  is_in_inclusions = std::find(inclusions.begin(), inclusions.end(), section_name) != inclusions.end();
        
        if ( (inclusions.empty() || is_in_inclusions) && (!is_in_exclusions || exclusions.empty())) {
            //result.push_back(section_name);
            return section_name;
        }
    }

    // If the result is empty and there is a fallback list, check if not in exclusions only
    if (result.empty() && !fallback_candidates.empty()) {
        for (const std::string& fallback_name : fallback_candidates) {
            // Check if the fallback section name exists in the PE file
            bool  is_in_exclusions = std::find(exclusions.begin(), exclusions.end(), fallback_name) != exclusions.end();
            if (!is_in_exclusions || exclusions.empty()) {
                //result.push_back(fallback_name);
                return fallback_name;
            }
        }

        // if still empty, keep it empty
    }


    return;
}

```gpt

#include <LIEF/LIEF.hpp>
#include <vector>
#include <string>

class PESection {
public:
    //LIEF::PE::Section section;
    LIEF::PE::Section* section;

    PESection(LIEF::PE::Section* sec) : section(sec) {}

    bool has_slack_space() const {
        return section->size() > section->virtual_size();
    }

    bool is_executable() const {
        return static_cast<size_t>(section->characteristics()) & static_cast<size_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
        
    }

    bool is_readable() const {
        return static_cast<size_t>(section->characteristics()) & static_cast<size_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
    }

    bool is_writable() const {
        return static_cast<size_t>(section->characteristics()) & static_cast<size_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);
    }

    uint64_t raw_data_size() const {
        return section->size();
    }

    std::string real_name() const {
        return section->name();
    }

    uint64_t virtual_size() const {
        return section->virtual_size();
    }

    // -- Modifiers --
    void change_name(const std::string& new_name) {
        section->name(new_name);
    }


};

class PEFile {
    std::unique_ptr<LIEF::PE::Binary> binary;

public:
    PEFile(const std::string& file_path) {
        binary = LIEF::PE::Parser::parse(file_path);
    }

    ~PEFile() {
        binary.reset(); // std::unique_ptr will delete the object
    }

    std::vector<std::string> api_imports() const {
        std::vector<std::string> imports;
        for (const auto& imp : binary->imports()) {
            for (const auto& entry : imp.entries()) {
                imports.push_back(entry.name());
            }
        }
        std::sort(imports.begin(), imports.end());
        return imports;
    }

    uint32_t checksum() const {
        return binary->optional_header().checksum();
    }

    uint32_t entrypoint() const {
        return binary->optional_header().addressof_entrypoint();
    }

    PESection entrypoint_section() const {
        return PESection(binary->section_from_rva(binary->optional_header().addressof_entrypoint()));
    }

    // -- Modifiers --
    void change_entrypoint(uint32_t new_entrypoint) {
        binary->optional_header().addressof_entrypoint(new_entrypoint);
    }

    void write(const std::string& file_path) {
        binary->write(file_path);
    }

    void add_section(const std::string& name, uint32_t virtual_size, uint32_t raw_size, uint32_t characteristics) {
        LIEF::PE::Section section;
        section.name(name);
        section.virtual_size(virtual_size);
        section.size(raw_size);
        section.characteristics(characteristics);
        binary->add_section(section);
    }

    void remove_section(const std::string& name) {
        binary->remove_section(name);
    }

    void change_section_name(const std::string& old_name, const std::string& new_name) {
        binary->get_section(old_name)->name(new_name);
    }

    void add_import(const std::string& library, const std::string& function) {
        LIEF::PE::ImportEntry entry;
        entry.name(function);
        binary->get_import(library)->add_entry(entry);
    }

    void add_library(const std::string& library) {
        binary->add_library(library);
    }


};
```