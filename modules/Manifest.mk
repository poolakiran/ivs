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

BASEDIR := $(dir $(lastword $(MAKEFILE_LIST)))
OVSDriver_BASEDIR := $(BASEDIR)/OVSDriver
flowtable_BASEDIR := $(BASEDIR)/flowtable
l2table_BASEDIR := $(BASEDIR)/l2table
luajit_BASEDIR := $(BASEDIR)/luajit
xbuf_BASEDIR := $(BASEDIR)/xbuf
pipeline_BASEDIR := $(BASEDIR)/pipeline
pipeline_bvs_BASEDIR := $(BASEDIR)/pipeline_bvs
pipeline_lua_BASEDIR := $(BASEDIR)/pipeline_lua
pipeline_standard_BASEDIR := $(BASEDIR)/pipeline_standard
ivs_common_BASEDIR := $(BASEDIR)/ivs
tcam_BASEDIR := $(BASEDIR)/tcam
action_BASEDIR := $(BASEDIR)/action
stats_BASEDIR := $(BASEDIR)/stats
lpm_BASEDIR := $(BASEDIR)/lpm
inband_BASEDIR := $(BASEDIR)/inband
nat_BASEDIR := $(BASEDIR)/nat
pipeline_reflect_BASEDIR := $(BASEDIR)/pipeline_reflect
host_stats_BASEDIR := $(BASEDIR)/host_stats
shared_debug_counter_BASEDIR := $(BASEDIR)/shared_debug_counter
