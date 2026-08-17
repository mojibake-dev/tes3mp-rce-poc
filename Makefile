# tes3mp-rce
#
#   make          build (fetches + builds CrabNet on first run, see `make deps`)
#   make deps     clone + build the pinned CrabNet only
#   make clean    remove the exploit binary
#   make distclean  also remove third_party/CrabNet
#
# Everything needed is either vendored (third_party/tes3mp) or fetched at a pinned commit
# (third_party/CrabNet), so a clean clone builds with no manual dependency hunting.
#
# Already have the trees? Point at them instead and nothing is fetched:
#   make CRABNET_SRC=/srv/fuzz/tes3mp/src/CrabNet CRABNET_LIB=/srv/fuzz/tes3mp/raknet/lib/libRakNetLibStatic.a
#   make RAKNET_INC=/srv/fuzz/tes3mp/raknet/include/raknet RAKNET_LIBDIR=/srv/fuzz/tes3mp/raknet/lib

CRABNET_REPO   ?= https://github.com/TES3MP/CrabNet.git
CRABNET_COMMIT ?= 19e66190e83f53bcdcbcd6513238ed2e54878a21   # the fork+commit TES3MP 0.8.1 links

THIRD_PARTY ?= third_party
CRABNET_SRC ?= $(THIRD_PARTY)/CrabNet
CRABNET_LIB ?= $(CRABNET_SRC)/build/lib/libRakNetLibStatic.a

RAKNET_INC    ?= $(CRABNET_SRC)/include/raknet
RAKNET_LIBDIR ?= $(dir $(CRABNET_LIB))
TES3MP_INC    ?= $(THIRD_PARTY)/tes3mp          # vendored NetworkMessages.hpp

CXX      ?= g++
CXXFLAGS ?= -O2 -w -std=c++17
INCLUDES  = -I$(RAKNET_INC) -I$(TES3MP_INC)
LDFLAGS   = -L$(RAKNET_LIBDIR)
LDLIBS    = -lRakNetLibStatic -lpthread

BIN = tes3mp-rce
SRC = src/tes3mp-rce.cc

all: $(BIN)

$(BIN): $(SRC) | $(CRABNET_LIB)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)
	@echo "built ./$(BIN) - run './$(BIN) --help'"

deps: $(CRABNET_LIB)

$(CRABNET_SRC)/.git:
	@echo "==> cloning CrabNet at $(CRABNET_COMMIT)"
	@mkdir -p $(THIRD_PARTY)
	git clone $(CRABNET_REPO) $(CRABNET_SRC)
	cd $(CRABNET_SRC) && git checkout -q $(CRABNET_COMMIT)

# Static library only: the DLL and samples are not needed and roughly double the build.
#
# -include cstdint is REQUIRED on GCC 13+. CrabNet dates from 2020 and relies on <cstdint> arriving
# transitively; newer libstdc++ no longer provides it, so Source/Utils/_FindFirst.h fails with
# "'intptr_t' was not declared in this scope". This force-includes it rather than patching the tree.
CRABNET_CXXFLAGS ?= -include cstdint

$(CRABNET_LIB): | $(CRABNET_SRC)/.git
	@echo "==> building CrabNet static library (a few minutes, once)"
	cmake -S $(CRABNET_SRC) -B $(CRABNET_SRC)/build \
	      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	      -DCMAKE_CXX_FLAGS="$(CRABNET_CXXFLAGS)" \
	      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	      -DCRABNET_ENABLE_SAMPLES=OFF \
	      -DCRABNET_ENABLE_DLL=OFF \
	      -DCRABNET_ENABLE_STATIC=ON
	cmake --build $(CRABNET_SRC)/build --target RakNetLibStatic -j$(shell nproc 2>/dev/null || echo 4)
	@test -f $@ || { echo "error: expected $@ after the CrabNet build"; exit 1; }

clean:
	rm -f $(BIN)

distclean: clean
	rm -rf $(CRABNET_SRC)

.PHONY: all deps clean distclean
