# Copyright 2016, Big Switch Networks, Inc.

LIBRARY := mgmt_interface_stats
$(LIBRARY)_SUBDIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(BUILDER)/lib.mk
