#include <iostream>
#include <random>
#include <vector>
#include <string>
#include <algorithm>
#include <array>
#include <cmath>

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

    static std::vector<uint8_t> to_little_endian_bytes_array(uint64_t va, bool is_64 = false) {
        size_t byte_count = is_64 ? 8 : 4;
        std::vector<uint8_t> bytes(byte_count);
        for (size_t i = 0; i < byte_count; ++i) {
            bytes[i] = static_cast<uint8_t>((va >> (i * 8)) & 0xFF);
        }
        return bytes;
    }

    // append vectors to vector
    static std::vector<uint8_t> append_vectors(std::vector<uint8_t> a, std::vector<uint8_t> b) {
        a.insert(a.end(), b.begin(), b.end());
        return a;
    }

    static size_t get_random_number(size_t min, size_t max) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }

    // ----- Shannon entropy helpers -----
    // The tool historically padded sections by fixed byte-count heuristics and
    // "hoped" the entropy dropped (it never measured it). These make entropy a
    // measured target: a byte histogram, the Shannon entropy of a histogram
    // (0..8 bits/byte), and convenience wrappers over a raw buffer.

    static std::array<size_t, 256> byte_histogram(const uint8_t* data, size_t len) {
        std::array<size_t, 256> counts{};
        for (size_t i = 0; i < len; ++i) {
            counts[data[i]]++;
        }
        return counts;
    }

    static double entropy_from_counts(const std::array<size_t, 256>& counts, size_t total) {
        if (total == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (size_t c : counts) {
            if (c == 0) {
                continue;
            }
            double p = static_cast<double>(c) / static_cast<double>(total);
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    static double compute_entropy(const uint8_t* data, size_t len) {
        return entropy_from_counts(byte_histogram(data, len), len);
    }

    static double compute_entropy(const std::vector<uint8_t>& data) {
        return compute_entropy(data.data(), data.size());
    }

    // Draw `n` bytes i.i.d. from a 256-bin frequency distribution. The result
    // has (statistically) the same byte histogram as the source - hence a
    // similar entropy and the same "does this look like data" profile - but it
    // is aperiodic and not a verbatim copy of any region. Used to produce
    // filler that resembles genuine section data instead of a constant run or a
    // 3-byte repeating pattern. Falls back to a plausible zeros-plus-ASCII
    // distribution when the source histogram is empty.
    static std::vector<uint8_t> sample_from_counts(const std::array<size_t, 256>& counts, size_t n, std::mt19937& gen) {
        std::vector<double> weights(counts.begin(), counts.end());
        bool any = false;
        for (double w : weights) {
            if (w > 0.0) { any = true; break; }
        }
        if (!any) {
            weights.assign(256, 0.0);
            weights[0x00] = 8.0;                       // padding/zeros, common in real data
            for (int c = 'a'; c <= 'z'; ++c) weights[c] = 1.0;
            for (int c = 'A'; c <= 'Z'; ++c) weights[c] = 0.5;
            weights[0x20] = 2.0;                        // space
        }
        std::discrete_distribution<int> dist(weights.begin(), weights.end());
        std::vector<uint8_t> out;
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) {
            out.push_back(static_cast<uint8_t>(dist(gen)));
        }
        return out;
    }

};