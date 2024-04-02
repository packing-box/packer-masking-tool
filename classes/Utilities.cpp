#include <iostream>
#include <random>
#include <vector>
#include <string>
#include <algorithm>

class Utilities
{
public:
    static void print(const std::string& str)
    {
        std::cout << str << std::endl;
    }

    static std::pair<std::string, std::string> select_random(std::vector<std::pair<std::string, std::string>> from_pairs, std::vector<std::pair<std::string, std::string>> exclusions){
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, from_pairs.size()-1);
        std::pair<std::string, std::string> random = from_pairs[dis(gen)];
        while(std::find(exclusions.begin(), exclusions.end(), random) != exclusions.end()){
            random = from_pairs[dis(gen)];
        }
        return random;
    }

    static std::vector<uint8_t> generateRandomBytes(size_t length) {
        std::vector<uint8_t> bytes(length);
        std::random_device rd; // Obtain a random number from hardware
        std::mt19937 eng(rd()); // Seed the generator
        std::uniform_int_distribution<> distr(0, 255); // Define the range

        for (auto& byte : bytes) {
            byte = static_cast<uint8_t>(distr(eng)); // Generate a random byte and assign it
        }

        return bytes;
    }

    static std::string select_section_name(const std::vector<std::string>& candidates, 
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
};