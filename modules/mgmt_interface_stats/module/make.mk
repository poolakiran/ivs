# Copyright 2016, Big Switch Networks, Inc.

THIS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
mgmt_interface_stats_INCLUDES := -I $(THIS_DIR)inc
mgmt_interface_stats_INTERNAL_INCLUDES := -I $(THIS_DIR)src
mgmt_interface_stats_DEPENDMODULE_ENTRIES := init:mgmt_interface_stats
