################################################################
#
#        Copyright 2017, Big Switch Networks, Inc.
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
#  lpm128 Unit Testing Module Makefile
#
#
#
###############################################################################
MODULE := lpm128_utest
NOMODULEMAKE := 1
TEST_MODULE :=  lpm128
DEPENDMODULES := AIM slot_allocator
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_POSIX=1
GLOBAL_CFLAGS += -DAIM_CONFIG_INCLUDE_MAIN=1
GLOBAL_CFLAGS += -I$(lpm128_BASEDIR)/module/src
OS_MAKE_CONFIG_AUTOSELECT := 1
include ../make/utestmodule.mk
