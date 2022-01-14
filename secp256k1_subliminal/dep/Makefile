CXX= g++
CXXFLAGS= -O2 -fPIC -std=c++14 -Wall -Wno-unused-function 
RM= rm -f

LIBS = -lm -lgmp -lcryptopp
INCS = -I./ -I./secp256k1_impl/

.SUFFIXES:
.SUFFIXES: .cpp .o

# Build objects
OBJ = crypto.o \
      crypto_c.o \
      secp256k1.o 

%.o:%.cpp
	$(CXX) -c $(CXXFLAGS) $(INCS) $< -o $@

all: libsecp256k1_subliminal.so

libsecp256k1_subliminal.so: $(OBJ)
	$(CXX) -shared -o $@ $(CXXFLAGS) $(LIBS) $^

# Do cleaning
.PHONY: clean
clean:
	-$(RM) *.o libsecp256k1_subliminal.so
	-$(RM) -r html/
