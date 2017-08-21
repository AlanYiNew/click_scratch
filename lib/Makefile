CURRENT_DIR := $(abspath $(lastword $(MAKEFILE_LIST)))


include ${RUMPRUN_BASE_DIR}/platform/sel4/rumprunlibs.mk
#Filter out ino.cc which is a inode class for file accessing under linux
CLICK_CCFILES:=$(filter-out ${SOURCE_DIR}/lib/ino.cc, $(wildcard ${SOURCE_DIR}/lib/*.cc))
#CLICK_HHFILES:=$(wildcard ${SOURCE_DIR}/lib/*.hh)
CLICK_OBJS :=$(patsubst %.cc,%.o,$(CLICK_CCFILES))
CLICK_LIBS :=$(SOURCE_DIR)/lib/libclick.a



${SOURCE_DIR}/lib/%.o: ${SOURCE_DIR}/lib/%.cc
	@echo "Making $@"
	$(RUMPRUN_CXX) -c \
		-I${SOURCE_DIR}/include \
		-DCLICK_USERLEVEL \
		-DHAVE_IP6 \
		$^ -o $@


$(CLICK_LIBS):$(CLICK_OBJS) 
	@echo Making $@ 
	ar rcs $@ $(CLICK_OBJS)

