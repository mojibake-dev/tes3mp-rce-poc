# tes3mp-rce
#
# Needs the RakNet/CrabNet headers + static lib that the TES3MP build links, and the TES3MP source
# tree for components/openmw-mp/NetworkMessages.hpp. Override either on the command line:
#
#   make RAKNET_DIR=/srv/fuzz/tes3mp/raknet TES3MP_SRC=/srv/fuzz/tes3mp/src/TES3MP
#
RAKNET_DIR ?= /srv/fuzz/tes3mp/raknet
TES3MP_SRC ?= /srv/fuzz/tes3mp/src/TES3MP

CXX      ?= g++
CXXFLAGS ?= -O2 -w -std=c++17
INCLUDES  = -I$(RAKNET_DIR)/include/raknet -I$(TES3MP_SRC)
LDFLAGS   = -L$(RAKNET_DIR)/lib
LDLIBS    = -lRakNetLibStatic -lpthread

BIN = tes3mp-rce
SRC = src/tes3mp-rce.cc

all: $(BIN)

$(BIN): $(SRC)
	@test -d "$(RAKNET_DIR)/include/raknet" || { \
	  echo "error: RakNet headers not found at $(RAKNET_DIR)/include/raknet"; \
	  echo "       set RAKNET_DIR=/path/to/raknet (see README.md)"; exit 1; }
	@test -f "$(TES3MP_SRC)/components/openmw-mp/NetworkMessages.hpp" || { \
	  echo "error: TES3MP source not found at $(TES3MP_SRC)"; \
	  echo "       set TES3MP_SRC=/path/to/TES3MP (see README.md)"; exit 1; }
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: all clean
