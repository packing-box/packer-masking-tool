#ifndef RAWSIZEEDITOR_HPP
#define RAWSIZEEDITOR_HPP

#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint> 
#include <fstream>

#include "CustomParser.hpp"

class RawSizeEditor {
public:
    RawSizeEditor(std::string filePath);

    void addOverlay(size_t overlaySize);

    size_t edit(float rawSizePercentage = 0.8, bool modeMaxFileSize = false, bool modeAllSections = false) ;

private:
    std::string filePath;
    CustomParser parser;


    size_t updateSectionHeaders(float rawSizePercentage = 0.0, bool modeMaxFileSize = false, bool modeAllSections = false);
    
};



#endif // RAWSIZEEDITOR_HPP