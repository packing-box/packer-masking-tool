# Compiler
CXX = g++

# File to test
FILE=upx_7z.exe
#FILE=SimpleTest.exe


# Compiler flags
CXXFLAGS = -Wall -std=c++17

# LIEF library
#LIEF = -I/usr/local/LIEF/include/LIEF -L/usr/local/LIEF/lib -lLIEF # DYNAMIC
LIEF = -I/usr/local/LIEF/include/LIEF -L/usr/local/LIEF/lib -l:libLIEF.a # STATIC

#STATIC_LINK = #-static-libgcc -static-libstdc++
PARAMS = $(CXXFLAGS) #$(STATIC_LINK)
# FROM 400KB to 7.1MB (9.1MB with static link of libstdc++ and libgcc)

SOURCE_DIR = src

DIR_CLASSES = $(SOURCE_DIR)/classes
# Executable name
EXEC = notpacked++

all: $(EXEC)

$(EXEC): main.o PEBinary.o PEBinaryModifiers.o CustomParser.o RawSizeEditor.o
	$(CXX) $(PARAMS) -o $(EXEC) PEBinary.o main.o PEBinaryModifiers.o RawSizeEditor.o CustomParser.o $(LIEF)
	rm -f *.o

main.o: $(SOURCE_DIR)/main.cpp $(DIR_CLASSES)/PEBinary.hpp 
	$(CXX) $(PARAMS) -c $(SOURCE_DIR)/main.cpp 

PEBinary.o: $(DIR_CLASSES)/PEBinary.cpp $(DIR_CLASSES)/PEBinary.hpp 
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinary.cpp $(LIEF)

PEBinaryModifiers.o: $(DIR_CLASSES)/PEBinaryModifiers.cpp $(DIR_CLASSES)/PEBinaryModifiers.hpp $(DIR_CLASSES)/CustomParser.hpp
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinaryModifiers.cpp $(LIEF)

CustomParser.o: $(DIR_CLASSES)/CustomParser.cpp $(DIR_CLASSES)/CustomParser.hpp
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/CustomParser.cpp 

RawSizeEditor.o: $(DIR_CLASSES)/RawSizeEditor.cpp $(DIR_CLASSES)/RawSizeEditor.hpp
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/RawSizeEditor.cpp

clean:
	rm -f *.o $(EXEC) 