#include <LIEF/LIEF.hpp>


// set checksum of the binary with the given value
bool set_checksum(LIEF::PE::Binary& binary, uint32_t checksum) {
    binary.optional_header().checksum(checksum);
    return true;
}