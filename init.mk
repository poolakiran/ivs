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

#
# The root of of our repository is here:
#
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

#
# Resolve submodule dependencies.
#
ifndef SUBMODULE_INFRA
  ifdef SUBMODULES
    SUBMODULE_INFRA := $(SUBMODULES)/infra
  else
    SUBMODULE_INFRA := $(ROOT)/submodules/infra
    SUBMODULES_LOCAL += infra
  endif
endif

ifndef SUBMODULE_BIGCODE
  ifdef SUBMODULES
    SUBMODULE_BIGCODE := $(SUBMODULES)/bigcode
  else
    SUBMODULE_BIGCODE := $(ROOT)/submodules/bigcode
    SUBMODULES_LOCAL += bigcode
  endif
endif

ifndef SUBMODULE_INDIGO
  ifdef SUBMODULES
    SUBMODULE_INDIGO := $(SUBMODULES)/indigo
  else
    SUBMODULE_INDIGO := $(ROOT)/submodules/indigo
    SUBMODULES_LOCAL += indigo
  endif
endif

ifndef SUBMODULE_LUAJIT2
  ifdef SUBMODULES
    SUBMODULE_LUAJIT2 := $(SUBMODULES)/luajit-2.0
  else
    SUBMODULE_LUAJIT2 := $(ROOT)/submodules/luajit-2.0
    SUBMODULES_LOCAL += luajit2
  endif
endif

ifndef SUBMODULE_LOXIGEN_ARTIFACTS
  ifdef SUBMODULES
    SUBMODULE_LOXIGEN_ARTIFACTS := $(SUBMODULES)/loxigen-artifacts
  else
    SUBMODULE_LOXIGEN_ARTIFACTS := $(ROOT)/submodules/loxigen-artifacts
    SUBMODULES_LOCAL += loxigen-artifacts
  endif
endif

ifndef SUBMODULE_SWITCHLIGHT_COMMON
  ifdef SUBMODULES
    SUBMODULE_SWITCHLIGHT_COMMON := $(SUBMODULES)/switchlight-common
  else
    SUBMODULE_SWITCHLIGHT_COMMON := $(ROOT)/submodules/switchlight-common
    SUBMODULES_LOCAL += switchlight-common
  endif
endif

export SUBMODULE_INFRA
export SUBMODULE_BIGCODE
export SUBMODULE_INDIGO
export SUBMODULE_LUAJIT2
export SUBMODULE_SWITCHLIGHT_COMMON
export BUILDER := $(SUBMODULE_INFRA)/builder/unix

MODULE_DIRS := $(ROOT)/modules \
               $(SUBMODULE_INFRA)/modules \
               $(SUBMODULE_BIGCODE)/modules \
               $(SUBMODULE_SWITCHLIGHT_COMMON)/modules \
               $(SUBMODULE_INDIGO)/modules

.show-submodules:
	@echo infra @ $(SUBMODULE_INFRA)
	@echo bigcode @ $(SUBMODULE_BIGCODE)
	@echo indigo @ $(SUBMODULE_INDIGO)
	@echo luajit2 @ $(SUBMODULE_LUAJIT2)
	@echo switchlight-common @ $(SUBMODULE_SWITCHLIGHT_COMMON)
