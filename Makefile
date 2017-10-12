#
# Copyright 2017, Data61
# Commonwealth Scientific and Industrial Research Organisation (CSIRO)
# ABN 41 687 119 230.
#
# This software may be distributed and modified according to the terms of
# the BSD 2-Clause license. Note that NO WARRANTY is provided.
# See "LICENSE_BSD2.txt" for details.
#
# @TAG(DATA61_BSD)
#
#

TARGETS := $(notdir ${SOURCE_DIR}).cdl
ADL := click_scrtach.camkes
TEMPLATES += ../../projects/global-components/templates/
TEMPLATES += templates 

PROJECT_BASE := $(PWD)
RUMPRUN_BASE_DIR := $(PWD)/libs/rumprun


all: default

include TimeServer/TimeServer.mk
include SerialServer/SerialServer.mk
include PCIConfigIO/PCIConfigIO.mk

include ${SOURCE_DIR}/lib/Makefile
include ${SOURCE_DIR}/elements/Makefile
include ${SOURCE_DIR}/components/rump_ether/rump_ether.mk
include ${SOURCE_DIR}/components/reverse_string/server.mk
include ${SOURCE_DIR}/components/central_routing/central_routing.mk
include ${SOURCE_DIR}/components/aq_broadcast/aq_broadcast.mk

include ${PWD}/tools/camkes/camkes.mk
.PHONY: clean
clean:
	rm $(ELEMENTS_OBJS) $(CLICK_LIBS)
