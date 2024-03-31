
#include <random>
#include <vector>

std::vector<uint8_t> generateRandomBytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    std::random_device rd; // Obtain a random number from hardware
    std::mt19937 eng(rd()); // Seed the generator
    std::uniform_int_distribution<> distr(0, 255); // Define the range

    for (auto& byte : bytes) {
        byte = static_cast<uint8_t>(distr(eng)); // Generate a random byte and assign it
    }

    return bytes;
}