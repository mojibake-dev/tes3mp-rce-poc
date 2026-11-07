# tes3mp-rce
#
#   make          build (fetches + builds CrabNet on first run, see `make deps`)
#   make deps     clone + build the pinned CrabNet only
#   make tools    build mk-control (gen-profile needs a TES3MP tree, see below)
#   make clean    remove the built binaries
#   make distclean  also remove third_party/CrabNet
#
# Retargeting a build other than stock 0.8.1 goes through tools/gen-profile, which derives
# the class layout from a TES3MP source tree with offsetof rather than from measurement.
# It needs headers this repo deliberately does not vendor, so it takes a path:
#   make gen-profile TES3MP_SRC=/path/to/TES3MP
# BasePlayer.hpp pulls components/esm, which pulls osg headers, so that tree's own build
# dependencies have to be reachable. Pass more include paths with GEN_PROFILE_INC if they
# are somewhere unusual.
#
# Everything needed is either vendored (third_party/tes3mp) or fetched at a pinned commit
# (third_party/CrabNet), so a clean clone builds with no manual dependency hunting.
#
# Already have the trees? Point at them instead and nothing is fetched:
#   make CRABNET_SRC=/path/to/CrabNet CRABNET_LIB=/path/to/libRakNetLibStatic.a
#   make RAKNET_INC=/path/to/raknet/include/raknet RAKNET_LIBDIR=/path/to/raknet/lib

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

# gen-profile compiles against a real TES3MP tree; mk-control only needs what we already have.
TES3MP_SRC      ?=
GEN_PROFILE_INC ?= $(if $(TES3MP_SRC),-I$(TES3MP_SRC))

# Fetching and building CrabNet is a prerequisite ONLY when we are using our own copy of it.
# Pointing RAKNET_LIBDIR or CRABNET_LIB at a tree that already exists must not trigger a clone,
# and it used to: CRABNET_LIB kept its default under $(THIRD_PARTY) whatever else you passed, so
# the order-only prerequisite fired and `make RAKNET_INC=... RAKNET_LIBDIR=...` -- the offline
# invocation the README documents -- tried to reach github and failed on any dark network.
CRABNET_DEP := $(CRABNET_LIB)
ifneq ($(filter command line,$(origin RAKNET_LIBDIR) $(origin CRABNET_LIB)),)
  CRABNET_DEP :=
endif

all: $(BIN)

$(BIN): $(SRC) | $(CRABNET_DEP)
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
# CrabNet dates from 2020 and relies on several standard headers arriving transitively; modern
# libstdc++/libc++ no longer pull them in, so force-include them. Without <cstdint>,
# Source/Utils/_FindFirst.h fails on 'intptr_t'; without <cstdlib>, DS_MemoryPool.h fails on
# 'malloc'/'free'; <cstring> covers the memcpy/strlen family for the same reason.
#
# -fwrapv -fno-strict-aliasing are REQUIRED with clang (macOS). CrabNet's congestion control
# (CCRakNetSlidingWindow) does signed-overflow arithmetic on ACK/sequence numbers, which is UB;
# clang -O2 "proves" the UB and replaces ShouldSendACKs() with __builtin_trap() (brk #1), so the
# background update thread SIGTRAPs the moment real packets flow to a reachable host. -fwrapv makes
# signed overflow defined and stops the miscompile. GCC does not need it, but it is harmless there.
CRABNET_CXXFLAGS ?= -include cstdint -include cstdlib -include cstring -fwrapv -fno-strict-aliasing

# clang (macOS) miscompiles CrabNet's congestion control (CCRakNetSlidingWindow::ShouldSendACKs) at -O2
# and -O1 into a bare __builtin_trap (brk #1): the background update thread SIGTRAPs the instant real
# packets flow to a reachable host. -fwrapv/-fno-strict-aliasing do not stop it; only dropping to -O0
# does. GCC compiles it correctly at -O2 (the proven Linux build), so switch the CrabNet optimisation
# level by compiler. Irrelevant to runtime: this is a two-connection client, not a throughput path.
# The per-config override keeps CMAKE_BUILD_TYPE=RelWithDebInfo (so the library name has no 'd' suffix).
CRABNET_OPT := -O2
ifneq (,$(findstring clang,$(shell $(CXX) --version 2>/dev/null)))
  CRABNET_OPT := -O0
endif

# CrabNet's bundled CmakeIncludes/PVS-Studio.cmake declares cmake_minimum_required(VERSION 2.8.12),
# and CMake 4.x removed compatibility with < 3.5. It is included unconditionally (CMakeLists.txt:44),
# so the CRABNET_ENABLE_PVS=OFF option cannot avoid it. This tells CMake to proceed with a 3.5 floor.
CMAKE_COMPAT ?= -DCMAKE_POLICY_VERSION_MINIMUM=3.5

$(CRABNET_LIB): | $(CRABNET_SRC)/.git
	@echo "==> building CrabNet static library (a few minutes, once)"
	cmake -S $(CRABNET_SRC) -B $(CRABNET_SRC)/build \
	      $(CMAKE_COMPAT) \
	      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	      -DCMAKE_CXX_FLAGS="$(CRABNET_CXXFLAGS)" \
	      -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="$(CRABNET_OPT) -g -DNDEBUG" \
	      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	      -DCRABNET_ENABLE_SAMPLES=OFF \
	      -DCRABNET_ENABLE_DLL=OFF \
	      -DCRABNET_ENABLE_STATIC=ON
	cmake --build $(CRABNET_SRC)/build --target RakNetLibStatic -j$(shell nproc 2>/dev/null || echo 4)
	@test -f $@ || { echo "error: expected $@ after the CrabNet build"; exit 1; }

tools: mk-control

mk-control: tools/mk-control.cc | $(CRABNET_DEP)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< -o $@ $(LDFLAGS) $(LDLIBS)
	@echo "built ./$@"

# Deliberately NOT vendored. gen-profile's whole job is to report the layout of the tree you
# point it at, so vendoring 0.8.1's headers would make it answer a question already answered by
# the baked-in defaults. Worse, its own header warns that a mismatched ABI produces wrong numbers
# that its assertions do not catch, so a stubbed osg::Vec3f would yield a confident wrong profile.
# The raknet include and link flags are not optional: BasePlayer.hpp pulls RakNetTypes.h and
# SystemAddress has an out-of-line constructor, so a header-only invocation fails at link.
gen-profile: tools/gen-profile.cc | $(CRABNET_DEP)
	@if [ -z "$(TES3MP_SRC)" ]; then \
		echo "gen-profile needs the TES3MP source tree for the build you are targeting:"; \
		echo "  make gen-profile TES3MP_SRC=/path/to/TES3MP"; \
		echo "Build it where the target's ABI matches; numbers derived under a different"; \
		echo "standard library are wrong and the tool cannot tell."; \
		exit 2; \
	fi
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(GEN_PROFILE_INC) -include cstdint -Wno-invalid-offsetof \
		$< -o $@ $(LDFLAGS) $(LDLIBS)
	@echo "built ./$@ - run './$@ <name> > target.profile', then './$(BIN) -F target.profile'"

clean:
	rm -f $(BIN) mk-control gen-profile

distclean: clean
	rm -rf $(CRABNET_SRC)

.PHONY: all deps tools clean distclean
