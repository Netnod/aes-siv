#===================================================================
#
# Makefile
# --------
# Makefile for building the siv_cmac core and
# top level simulation.
#
#
# Author: Joachim Strombergson
#
# Copyright (c) 2019, The Swedish Post and Telecom Authority (PTS)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#===================================================================
AES_SRC_PATH = ../../aes/src/rtl
AES_SRC = $(AES_SRC_PATH)/aes_core.v $(AES_SRC_PATH)/aes_encipher_block.v $(AES_SRC_PATH)/aes_key_mem.v  $(AES_SRC_PATH)/aes_sbox.v

CMAC_SRC = ../../cmac/src/rtl/cmac_core.v $(AES_SRC)
TB_CMAC_SRC = ../../cmac/src/tb/tb_cmac_core.v

CORE_SRC = ../src/rtl/aes_siv_core.v $(CMAC_SRC)
TB_CORE_SRC = ../src/tb/tb_aes_siv_core.v ../src/tb/tb_core_mem.v

TOP_SRC = ../src/rtl/aes_siv.v ../src/tb/tb_core_mem.v $(CORE_SRC)

WRAPPER_SRC = ../src/util/wrapper_aes_siv_core.v $(CORE_SRC)

CC = iverilog
CC_FLAGS = -Wall

LINT = verilator
LINT_FLAGS = +1364-2001ext+ --lint-only  -Wall -Wno-fatal -Wno-DECLFILENAME


all: top.sim core.sim wrapper.sim


top.sim: $(TOP_SRC)
	$(CC) $(CC_FLAGS) -o top.sim $(TOP_SRC)


core.sim: $(TB_CORE_SRC) $(CORE_SRC)
	$(CC) $(CC_FLAGS) -o core.sim $(TB_CORE_SRC) $(CORE_SRC)


wrapper.sim: $(WRAPPER_SRC)
	$(CC) $(CC_FLAGS) -o wrapper.sim $(WRAPPER_SRC)


sim-top: top.sim
	./top.sim


sim-core: core.sim
	./core.sim


sim-cmac: cmac.sim
	./cmac.sim


lint:  $(CORE_SRC)
	$(LINT) $(LINT_FLAGS) $(CORE_SRC)


lint_top:  $(TOP_SRC)
	$(LINT) $(LINT_FLAGS) $(TOP_SRC)


lint_wrapper:  $(WRAPPER_SRC)
	$(LINT) $(LINT_FLAGS) $(WRAPPER_SRC)


clean:
	rm -f top.sim
	rm -f core.sim
	rm -f wrapper.sim

help:
	@echo "Build system for simulation of AES Verilog core"
	@echo ""
	@echo "Supported targets:"
	@echo "------------------"
	@echo "all:          Build all simulation targets."
	@echo "core.sim:     Build core level simulation target."
	@echo "cmac.sim:     Build cmac core simulation target."
	@echo "sim-core:     Run core level simulation."
	@echo "sim-cmac:     Run cmac core simulation."
	@echo "lint:         Lint all rtl source files."
	@echo "clean:        Delete all built files."

#===================================================================
# EOF Makefile
#===================================================================
