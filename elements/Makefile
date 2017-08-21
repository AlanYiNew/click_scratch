CURRENT_DIR := $(abspath $(lastword $(MAKEFILE_LIST)))


include ${RUMPRUN_BASE_DIR}/platform/sel4/rumprunlibs.mk
ELEMENTS_CCFILES:=$(wildcard ${SOURCE_DIR}/elements/*/*.cc)
ELEMENTS_HHFILES:=$(wildcard ${SOURCE_DIR}/elements/*/*.hh)
ELEMENTS_HHFILES+=$(wildcard ${SOURCE_DIR}/elements/*/*.h)
CLICK_LIB_HEADER:=$(wildcard ${SOURCE_DIR}/include/*.h)

#This fuking file is broken
ELEMENTS_CCFILES:=$(filter-out ${SOURCE_DIR}/elements/analysis/fromflandump.cc, ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out ${SOURCE_DIR}/elements/analysis/fromflandump.hh, ${ELEMENTS_HHFILES})

#Broken file again
ELEMENTS_CCFILES:=$(filter-out ${SOURCE_DIR}/elements/tcpudp/statelesstcpresp.cc, ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out ${SOURCE_DIR}/elements/tcpudp/statelesstcpresp.hh, ${ELEMENTS_HHFILES})

#It seems that the configure script recognize ipsec,aqm can not be supported
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/ipsec/*), ${ELEMENTS_CCFILES})
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/aqm/*), ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/ipsec/*), ${ELEMENTS_HHFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/aqm/*), ${ELEMENTS_HHFILES})

#We don't build linux module
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/linuxmodule/*), ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/linuxmodule/*), ${ELEMENTS_HHFILES})

#We don't use DPDK
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/*dpdk*), ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/*dpdk*), ${ELEMENTS_HHFILES})

#We don't user rawsocket
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/rawsocket.cc), ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/rawsocket.hh), ${ELEMENTS_HHFILES})

#This thing seems linux platfomr relervant
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/fromhost.cc), ${ELEMENTS_CCFILES})
ELEMENTS_CCFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/tohost.cc), ${ELEMENTS_CCFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/fromhost.hh), ${ELEMENTS_HHFILES})
ELEMENTS_HHFILES:=$(filter-out $(wildcard ${SOURCE_DIR}/elements/userlevel/tohost.hh), ${ELEMENTS_HHFILES})


ELEMENTS_OBJS :=$(patsubst %.cc,%.o,$(ELEMENTS_CCFILES))

#It seems that HAVE_IP6  are not defined in config.h, just simply define it here so that hacking it to compile
%.o: %.cc $(CLICK_LIBS) $(ELEMENTS_HHFILES) 
	@echo "Making $@"
	$(RUMPRUN_CXX)  \
		-I${SOURCE_DIR}/include -c\
		-I${SOURCE_DIR} \
		-I ${RUMP_BUILD_DIR}/x86_64/rumprun/rumprun-x86_64/include/c++ \
		-include ${SOURCE_DIR}/include/click/config.h \
		-DCLCIK_USERLEVEL \
		-DHAVE_IP6 \
		-DHAVE_PCAP \
		-lclick \
		$< -o $@


 


