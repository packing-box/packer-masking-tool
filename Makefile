
PARAMS = -I/usr/local/LIEF/include/LIEF -L/usr/local/LIEF/lib -lLIEF

all: main.cpp
	g++ main.cpp -o main.o $(PARAMS)

run_test:
	./main.o SimpleTest.exe
	wine new_binary.exe

FILE=upx_7z.exe
#FILE=SimpleTest.exe
run_alterations:
	g++ alterations.cpp -o alterations.o $(PARAMS)
	./alterations.o $(FILE)
	wine modified_$(FILE)

run_all:
	g++ main.cpp -o main.o $(PARAMS)
	./main.o SimpleTest.exe
	wine new_binary.exe

test_alterations:
	g++ alterations.cpp -o alterations.o $(PARAMS)
	./alterations.o win-snap.exe

clean:
	rm -f *.o