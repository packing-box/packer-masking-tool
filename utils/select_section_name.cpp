#include <vector>
#include <string>
#include <algorithm> // for std::find

// for random selection
#include <random>


std::string select_section_name(const std::vector<std::string>& candidates, 
                                             const std::vector<std::string>& fallback_candidates = {},
                                             const std::vector<std::string>& inclusions = {}, 
                                             const std::vector<std::string>& exclusions = {}) {

    // Include sections if their names are in the 'candidates' and 'inclusions', excluding any in 'exclusions'
    for (const std::string& section_name : candidates) {

        bool  is_in_exclusions = std::find(exclusions.begin(), exclusions.end(), section_name) != exclusions.end();
        bool  is_in_inclusions = std::find(inclusions.begin(), inclusions.end(), section_name) != inclusions.end();
        
        if ( (inclusions.empty() || is_in_inclusions) && (!is_in_exclusions || exclusions.empty())) {
            //result.push_back(section_name);
            return section_name;
        }
    }

    // If the result is empty and there is a fallback list, select randomly from the fallback list
    if ( !fallback_candidates.empty()) {
        // Select a random section name from the fallback candidates
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, fallback_candidates.size()-1);
        return fallback_candidates[dis(gen)];

    }


    return "";
}