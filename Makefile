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





DIR_CLASSES = classes
# Executable name
EXEC = packer_masker.elf

all: $(EXEC)

$(EXEC): main.o PEBinary.o PEBinaryModifiers.o
	$(CXX) $(PARAMS) -o $(EXEC) PEBinary.o main.o PEBinaryModifiers.o $(LIEF)
	rm -f *.o

main.o: main.cpp $(DIR_CLASSES)/PEBinary.hpp
	$(CXX) $(PARAMS) -c main.cpp 

PEBinary.o: $(DIR_CLASSES)/PEBinary.cpp $(DIR_CLASSES)/PEBinary.hpp 
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinary.cpp $(LIEF)

PEBinaryModifiers.o: $(DIR_CLASSES)/PEBinaryModifiers.cpp $(DIR_CLASSES)/PEBinaryModifiers.hpp
	$(CXX) $(PARAMS) -c $(DIR_CLASSES)/PEBinaryModifiers.cpp $(LIEF)

run_test: $(EXEC)
	./$(EXEC) $(FILE)
	wine modified_$(FILE)

raw_size_editor: edit_raw_size.cpp
	$(CXX) $(PARAMS) -o raw_size_editor edit_raw_size.cpp

reset_7z:
	rm upx_7z.exe
	cp upx_7z.exe.bak upx_7z.exe

clean:
	rm -f *.o $(EXEC) 