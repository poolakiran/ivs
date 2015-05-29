################################################################
#
#        Copyright 2013, Big Switch Networks, Inc.
#
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#        http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
################################################################

###############################################################################
#
#  inband Unit Testing Module Makefile
#
#
#
###############################################################################
MODULE := inband_utest
NOMODULEMAKE := 1
TEST_MODULE :=  inband
DEPENDMODULES := AIM loci indigo PPE IOF debug_counter xbuf slshared OS
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_POSIX=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MODULES_INIT=1

LIBNL_CFLAGS := $(shell pkg-config --cflags libnl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-genl-3.0)
LIBNL_CFLAGS += $(shell pkg-config --cflags --silence-errors libnl-route-3.0)
LIBNL_LIBS := $(shell pkg-config --libs libnl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-genl-3.0)
LIBNL_LIBS += $(shell pkg-config --libs --silence-errors libnl-route-3.0)
GLOBAL_CFLAGS += $(LIBNL_CFLAGS)
GLOBAL_LINK_LIBS += $(LIBNL_LIBS)

OS_MAKE_CONFIG_AUTOSELECT := 1
include ../make/utestmodule.mk
