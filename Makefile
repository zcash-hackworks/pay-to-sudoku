OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128
LDFLAGS += -flto

DEPSRC=depsrc
DEPINST=depinst

LDLIBS += -L $(DEPINST)/lib -Wl,-rpath $(DEPINST)/lib -L . -lsnark -lgmpxx -lgmp
LDLIBS += -lboost_system

all:
	$(CXX) -o snark/lib.o snark/lib.cpp -c $(CXXFLAGS)
	$(CXX) -o snark/sha256.o snark/sha256.c -c $(CXXFLAGS)
	$(CXX) -shared -o libmysnark.so snark/lib.o snark/sha256.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	mkdir -p target/debug
	mkdir -p target/release
	cp libmysnark.so target/debug
	cp libmysnark.so target/release

clean:
	$(RM) snark/sha256.o
	$(RM) snark/lib.o libmysnark.so target/debug/libmysnark.so target/release/libmysnark.so
