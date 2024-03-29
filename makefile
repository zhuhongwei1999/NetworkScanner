CXX      = g++
CXXFLAGS = -g -I.
CPPFLAGS = -DDEBUG
LIBS     =

obj      = main.o \
           port_scanner.o \
           ip_scanner.o

exe      = scan

all: ${exe}

${exe}: ${obj}
	${CXX} $^ ${LIBS} -o $@

.SUFFIXES:
.SUFFIXES: .cpp .o
%.o:%.cpp
	$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

clean:
	-rm *.o ${exe}
