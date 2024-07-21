# Compiler
CXX = g++

# File to test
FILE=upx_7z.exe
#FILE=SimpleTest.exe


# Compiler flags
CXXFLAGS = -Wall -std=c++11

# LIEF library
LIEF = -I/usr/local/LIEF/include/LIEF -L/usr/local/LIEF/lib -lLIEF
PARAMS = $(CXXFLAGS)



SOURCE_DIR = src

DIR_CLASSES = $(SOURCE_DIR)/classes
# Executable name
EXEC = notpacked++

all: $(EXEC)

$(EXEC): main.o PEBinary.o PEBinaryModifiers.o
	$(CXX) $(PARAMS) -o $(EXEC) PEBinary.o main.o PEBinaryModifiers.o $(LIEF)
	rm -f *.o

main.o: $(SOURCE_DIR)/main.cpp $(DIR_CLASSES)/PEBinary.hpp
	$(CXX) $(PARAMS) -c $(SOURCE_DIR)/main.cpp 

PEBinary.o: $(DIR_CLASSES)/PEBinary.cpp $(DIR_CLASSES)/PEBinary.hpp 
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinary.cpp $(LIEF)

PEBinaryModifiers.o: $(DIR_CLASSES)/PEBinaryModifiers.cpp $(DIR_CLASSES)/PEBinaryModifiers.hpp
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinaryModifiers.cpp $(LIEF)

run_test: $(EXEC)
	rm -f output_$(FILE)
	rm -f $(FILE) && cp $(FILE).bak $(FILE) && sha256sum $(FILE)
	./$(EXEC) $(FILE) && sha256sum output_$(FILE)
	wine output_$(FILE)

raw_size_editor: edit_raw_size.cpp
	$(CXX) $(PARAMS) -o raw_size_editor edit_raw_size.cpp

clean:
	rm -f *.o $(EXEC) 
