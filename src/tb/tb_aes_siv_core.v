//======================================================================
//
// tb_aes_siv_core.v
// -----------------
// Testbench for the aes_siv_core.
// Testvectors from RFC 5297:
// https://tools.ietf.org/html/rfc5297
//
// Debugged using the aes-siv model by Daniel F Franke:
// https://github.com/dfoxfranke/libaes_siv
//
//
// Author: Joachim Strombergson
//
// Copyright (c) 2019, The Swedish Post and Telecom Authority (PTS)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
//======================================================================

module tb_aes_siv_core();

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam DEBUG     = 1;
  localparam DEBUG_MEM = 1;

  localparam CLK_HALF_PERIOD = 1;
  localparam CLK_PERIOD      = 2 * CLK_HALF_PERIOD;

  localparam AEAD_AES_SIV_CMAC_256 = 1'h0;
  localparam AEAD_AES_SIV_CMAC_512 = 1'h1;

  localparam AES_BLOCK_SIZE = 128;

  localparam TIMEOUT_CYCLES = 10000;

  reg [127 : 0] testreg;


  //----------------------------------------------------------------
  // Register and Wire declarations.
  //----------------------------------------------------------------
  reg [31 : 0]  cycle_ctr;
  reg [31 : 0]  error_ctr;
  reg [31 : 0]  tc_ctr;
  reg           tc_correct;
  reg           debug_dut;
  reg           show_aes;
  reg           show_cmac;
  reg           show_s2v;
  reg           show_ctr;

  reg            tb_clk;
  reg            tb_reset_n;
  reg            dut_encdec;
  reg [511 : 0]  dut_key;
  reg            dut_mode;
  reg            dut_start;
  reg [15 :0]    dut_ad_start;
  reg [19 :0]    dut_ad_length;
  reg [15 :0]    dut_nonce_start;
  reg [19 :0]    dut_nonce_length;
  reg [15 :0]    dut_pc_start;
  reg [19 :0]    dut_pc_length;
  wire           dut_cs;
  wire           dut_we;
  wire           dut_ack;
  wire [15 : 0]  dut_addr;
  wire [127 : 0] dut_block_rd;
  wire [127 : 0] dut_block_wr;
  wire [127 : 0] dut_tag_in;
  wire [127 : 0] dut_tag_out;
  wire           dut_tag_ok;
  wire           dut_ready;

  reg            tb_debug;
  reg            tb_debug_mem;


  //----------------------------------------------------------------
  // Instantiations.
  //----------------------------------------------------------------
  aes_siv_core dut(
                   .clk(tb_clk),
                   .reset_n(tb_reset_n),

                   .encdec(dut_encdec),
                   .key(dut_key),
                   .mode(dut_mode),
                   .start(dut_start),

                   .ad_start(dut_ad_start),
                   .ad_length(dut_ad_length),

                   .nonce_start(dut_nonce_start),
                   .nonce_length(dut_nonce_length),

                   .pc_start(dut_pc_start),
                   .pc_length(dut_pc_length),

                   .cs(dut_cs),
                   .we(dut_we),
                   .ack(dut_ack),
                   .addr(dut_addr),
                   .block_rd(dut_block_rd),
                   .block_wr(dut_block_wr),

                   .tag_in(dut_tag_in),
                   .tag_out(dut_tag_out),
                   .tag_ok(dut_tag_ok),
                   .ready(dut_ready)
                  );


  // Support memory.
  tb_core_mem mem(
                  .clk(tb_clk),
                  .reset_n(tb_reset_n),
                  .cs(dut_cs),
                  .we(dut_we),
                  .ack(dut_ack),
                  .addr(dut_addr),
                  .block_wr(dut_block_wr),
                  .block_rd(dut_block_rd)
                  );


  //----------------------------------------------------------------
  // clk_gen
  //
  // Always running clock generator process.
  //----------------------------------------------------------------
  always
    begin : clk_gen
      #CLK_HALF_PERIOD;
      tb_clk = !tb_clk;
    end // clk_gen


  //----------------------------------------------------------------
  // sys_monitor()
  //
  // An always running process that creates a cycle counter and
  // conditionally displays information about the DUT.
  //----------------------------------------------------------------
  always
    begin : sys_monitor
      #(CLK_PERIOD);
      cycle_ctr = cycle_ctr + 1;

      if (cycle_ctr == TIMEOUT_CYCLES)
        begin
          $display("Timout reached after %d cycles before simulation ended.",
                   cycle_ctr);
          $stop;
        end

      if (debug_dut)
        dump_dut_state();
    end


  //----------------------------------------------------------------
  // dump_dut_state()
  //
  // Dump the state of the dump when needed.
  //----------------------------------------------------------------
  task dump_dut_state;
    begin
      $display("\n");
      $display("cycle:  0x%016x", cycle_ctr);
      $display("Inputs and outputs:");
      $display("ready: 0x%01x, start: 0x%01x, tag: 0x%016x",
               dut.ready, dut.start, dut.tag_out);
      $display("");

      if (show_aes)
        begin
          $display("AES:");
          $display("aes_ready: 0x%01x, aes_init: 0x%01x, aes_next = 0x%01x",
                   dut.aes_ready, dut.aes_init, dut.aes_next);
          $display("aes_keylen: 0x%01x, aes_key: 0x%032x", dut.aes_keylen, dut.aes_key);
          $display("aes_block: 0x%016x, aes_result: 0x%016x", dut.aes_block, dut.aes_result);
          $display("");
        end

      if (show_cmac)
        begin
          $display("CMAC:");
          $display("cmac_inputs: 0x%01x", dut.cmac_inputs);
          $display("cmac_ready: 0x%01x, cmac_init: 0x%01x, cmac_next: 0x%01x, cmac_finalize = 0x%01x,  cmac_final_length = 0x%02x",
                   dut.cmac_ready, dut.cmac_init, dut.cmac_next, dut.cmac_finalize, dut.cmac_final_size);
          $display("cmac_keylen: 0x%01x, cmac_key: 0x%032x", dut.cmac_keylen, dut.cmac_key);
          $display("cmac_block: 0x%016x, cmac_result: 0x%016x", dut.cmac_block, dut.cmac_result);
          $display("");
        end

      if (show_s2v)
        begin
          $display("ad_zlen: 0x%01x, nonce_zlen: 0x%01x, pc_zlen: 0x%01x",
                   dut.ad_zlen, dut.nonce_zlen, dut.pc_zlen);
          $display("d_reg: 0x%016x, d_new: 0x%016x, d_we: 0x%01x",
                   dut.d_reg, dut.d_new, dut.d_we);
          $display("v_reg: 0x%016x, v_we: 0x%01x",
                   dut.v_reg, dut.v_we);
          $display("x_reg: 0x%016x, x_new: 0x%016x, x_we: 0x%01x",
                   dut.x_reg, dut.x_new, dut.x_we);
          $display("\n");
        end

      $display("Control:");
      $display("ctrl_reg: 0x%02x, ctrl_new: 0x%02x, ctrl_we: 0x%01x",
               dut.core_ctrl_reg, dut.core_ctrl_new, dut.core_ctrl_we);
      $display("addr_reg: 0x%04x, addr_new: 0x%04x, addr_we: 0x%01x, addr_set: 0x%01x, addr_inc: 0x%01x, addr_mux: 0x%01x",
               dut.addr_reg, dut.addr_new, dut.addr_we, dut.addr_set, dut.addr_inc, dut.addr_mux);
      $display("block_ctr_reg: 0x%04x, block_ctr_new: 0x%04x, block_ctr_we: 0x%01x",
               dut.block_ctr_reg, dut.block_ctr_new, dut.block_ctr_we);
      $display("\n");
    end
  endtask // dump_dut_state


  //----------------------------------------------------------------
  // reset_dut()
  //
  // Toggle reset to put the DUT into a well known state.
  //----------------------------------------------------------------
  task reset_dut;
    begin
      $display("TB: Resetting dut.");
      tb_reset_n = 0;
      #(2 * CLK_PERIOD);
      tb_reset_n = 1;
    end
  endtask // reset_dut


  //----------------------------------------------------------------
  // display_test_results()
  //
  // Display the accumulated test results.
  //----------------------------------------------------------------
  task display_test_results;
    begin
      $display("");
      if (error_ctr == 0)
        begin
          $display("%02d test completed. All test cases completed successfully.", tc_ctr);
        end
      else
        begin
          $display("%02d tests completed - %02d test cases did not complete successfully.",
                   tc_ctr, error_ctr);
        end
    end
  endtask // display_test_results


  //----------------------------------------------------------------
  // init_sim()
  //
  // Initialize all counters and testbed functionality as well
  // as setting the DUT inputs to defined values.
  //----------------------------------------------------------------
  task init_sim;
    begin
      cycle_ctr  = 0;
      error_ctr  = 0;
      tc_ctr     = 0;
      debug_dut  = 0;

      show_aes   = 0;
      show_cmac  = 0;
      show_s2v   = 0;
      show_ctr   = 0;

      tb_clk           = 1'h0;
      tb_reset_n       = 1'h1;
      dut_encdec       = 1'h0;
      dut_key          = 512'h0;
      dut_mode         = 1'h0;
      dut_start        = 1'h0;
      dut_ad_start     = 16'h0;
      dut_ad_length    = 20'h0;
      dut_nonce_start  = 16'h0;
      dut_nonce_length = 20'h0;
      dut_pc_start     = 16'h0;
      dut_pc_length    = 20'h0;

      tb_debug         = 1'h1;
    end
  endtask // init_sim


  //----------------------------------------------------------------
  // inc_tc_ctr
  //----------------------------------------------------------------
  task inc_tc_ctr;
    tc_ctr = tc_ctr + 1;
  endtask // inc_tc_ctr


  //----------------------------------------------------------------
  // inc_error_ctr
  //----------------------------------------------------------------
  task inc_error_ctr;
    error_ctr = error_ctr + 1;
  endtask // inc_error_ctr


  //----------------------------------------------------------------
  // pause_finish()
  //
  // Pause for a given number of cycles and then finish sim.
  //----------------------------------------------------------------
  task pause_finish(input [31 : 0] num_cycles);
    begin
      $display("Pausing for %04d cycles and then finishing hard.", num_cycles);
      #(num_cycles * CLK_PERIOD);
      $finish;
    end
  endtask // pause_finish


  //----------------------------------------------------------------
  // wait_ready()
  //
  // Wait for the ready flag to be set in dut.
  //----------------------------------------------------------------
  task wait_ready;
    begin : wready
      while (dut_ready == 0)
        #(CLK_PERIOD);
    end
  endtask // wait_ready


  //----------------------------------------------------------------
  // wait_ack()
  //
  // Wait for the ack from memory to be asserted.
  //----------------------------------------------------------------
  task wait_ack;
    begin : wait_ack
      #(2 * CLK_PERIOD);

      while (!dut_ack)
        #(CLK_PERIOD);
    end
  endtask // wait_ack


  //----------------------------------------------------------------
  // write_block()
  //
  // Write the given block to the test mem.
  //----------------------------------------------------------------
  task write_block(input [15 : 0] addr,
                  input [127 : 0] block);
    begin
      $display("*** Writing 0x%032x to 0x%04x.", block, addr);
      mem.mem[addr] = block;
    end
  endtask // write_block


  //----------------------------------------------------------------
  // read_block()
  //
  // Read the block at the address from the test mem.
  //----------------------------------------------------------------
  task read_block(input [15 : 0] addr);
    begin
      $display("*** Read 0x%032x from 0x%04x.", mem.mem[addr], addr);
    end
  endtask // read_block


  //----------------------------------------------------------------
  // dump_mem()
  //
  // Dump the memory contents in the given address range. This
  // task directly accesses the tet memory without using the API.
  //----------------------------------------------------------------
  task dump_mem(input [15 : 0] start_addr, input [15 : 0] end_addr);
    begin : dump_mem
      reg [15 : 0] i;

      $display("Contents of memory in range 0x%04x to 0x%04x:", start_addr, end_addr);

      for (i = start_addr ; i <= end_addr ; i = i + 1)
          $display("0x%04x: 0x%032x", i, mem.mem[i]);
    end
  endtask // dump_mem


  //----------------------------------------------------------------
  // tc1_reset_state
  //
  // Check that registers in the dut are being correctly reset.
  //----------------------------------------------------------------
  task tc1_reset_state;
    begin : tc1
      inc_tc_ctr();
      debug_dut = 1;
      $display("TC1: Check that the dut registers are correctly reset.");
      #(2 * CLK_PERIOD);
      reset_dut();
      #(2 * CLK_PERIOD);
    end
  endtask // tc1_reset_state


  //----------------------------------------------------------------
  // tc2_s2v_init
  //
  // Check that pulling s2v_init perform cmac operation in all
  // zero data and sets the d_reg correctly. Key from RFC 5297.
  //----------------------------------------------------------------
  task tc2_s2v_init;
    begin : tc2
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;

      $display("TC2: Check that s2v_init works as expected.");
      dut_key  = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0, {128{1'h0}},
                   128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff, {128{1'h0}}};
      dut_mode = AEAD_AES_SIV_CMAC_256;

      #(2 * CLK_PERIOD);
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_dut = 0;

      if (dut.d_reg != 128'h0e04dfafc1efbf040140582859bf073a)
        begin
          $display("TC2: ERROR - d_reg incorrect. Expected 0x0e04dfafc1efbf040140582859bf073a, got 0x%032x.", dut.d_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC2: SUCCESS - d_reg correctly initialized.");
      else
        $display("TC2: NO SUCCESS - d_reg not correctly initialized.");
      $display("");
    end
  endtask // tc2


  //----------------------------------------------------------------
  // tc3_s2v_finalize_no_ad
  //
  // Check that pulling s2v_finalize before no AD has been
  // processed leads to v_reg getting the CMAC for all one data.
  // Key from RFC 5297.
  //----------------------------------------------------------------
  task tc3_s2v_finalize_no_ad;
    begin : tc2
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;

      $display("TC3: Check that v_reg is set when no AD has been processed.");

      $display("TC3: Resetting DUT first.");
      reset_dut();
      #(2 * CLK_PERIOD);

      $display("TC3: Calling s2v finalize.");
      dut_key  = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0, {128{1'h0}},
                   128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff, {128{1'h0}}};
      dut_mode = AEAD_AES_SIV_CMAC_256;

      #(2 * CLK_PERIOD);
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_dut = 0;

      if (dut.v_reg != 128'h949f99cbcc3eb5da6d3c45d0f59aa9c7)
        begin
          $display("TC2: ERROR - v_reg incorrect. Expected 0x949f99cbcc3eb5da6d3c45d0f59aa9c7, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TCC: SUCCESS - v_reg correctly set.");
      else
        $display("TCC: NO SUCCESS - v_reg not correctly set.");
      $display("");
    end
  endtask // tc3_s2v_finalize_no_ad


  //----------------------------------------------------------------
  // tc3_s2v_ad1
  //
  // Check that pulling s2v_finalize before no AD has been
  // processed leads to v_reg getting the CMAC for all one data.
  // Key from RFC 5297.
  //----------------------------------------------------------------
  task tc4_s2v_ad1;
    begin : tc2
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;

      $display("TC3: Check that v_reg is set when no AD has been processed.");

      $display("TC3: Resetting DUT first.");
      reset_dut();
      #(2 * CLK_PERIOD);

      $display("TC3: Calling s2v finalize.");
      dut_key  = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0, {128{1'h0}},
                   128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff, {128{1'h0}}};
      dut_mode = AEAD_AES_SIV_CMAC_256;

      #(2 * CLK_PERIOD);
      wait_ready();

      #(2 * CLK_PERIOD);
      debug_dut = 0;

      if (dut.v_reg != 128'h949f99cbcc3eb5da6d3c45d0f59aa9c7)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x949f99cbcc3eb5da6d3c45d0f59aa9c7, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - v_reg correctly set.");
      else
        $display("TC: NO SUCCESS - v_reg not correctly set.");
      $display("");
    end
  endtask // tc4_s2v_ad1


  //----------------------------------------------------------------
  // test_block_bits
  //
  // Check that the core calculates the correct number of blocks
  // and bits in the last block.
  //----------------------------------------------------------------
  task test_block_bits;
    begin : test_block_bits
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;

      $display("TCY: Check that core calculated number blocks, bits correctly");

      // Set access mux to TB. Write data to address 0x0040.
      dut_ad_start  = 16'h00a0;
      dut_ad_length = 20'h0;

      dut_nonce_start  = 16'h55aa;
      dut_nonce_length = 20'h4e31;

      dut_pc_start  = 16'hbeef;
      dut_pc_length = 20'h17;

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;


      $display("All calculations should be done. Showing results:");
      $display("ad_start_reg: 0x%04x, ad_length_reg: 0x%06x, ad_zlen: 0x%01x, ad_num_blocks: 0x%05x, ad_final_size: 0x%02x",
               dut.ad_start_reg, dut.ad_length_reg, dut.ad_zlen, dut.ad_num_blocks, dut.ad_final_size);
      $display("nonce_start_reg: 0x%04x, nonce_length_reg: 0x%06x, nonce_zlen: 0x%01x, nonce_num_blocks: 0x%05x, nonce_final_size: 0x%02x",
               dut.nonce_start_reg, dut. nonce_length_reg, dut.nonce_zlen, dut.nonce_num_blocks, dut.nonce_final_size);
      $display("pc_start_reg: 0x%04x, pc_length_reg: 0x%06x, pc_zlen: 0x%01x, pc_num_blocks: 0x%05x, pc_final_size: 0x%02x",
               dut.ad_start_reg, dut.pc_length_reg, dut.pc_zlen, dut.pc_num_blocks, dut.pc_final_size);
    end
  endtask // test_block_bits


  //----------------------------------------------------------------
  // test_all_zero_s2v
  //
  // Test that the core handles the case when all inputs have
  // zero length.
  //----------------------------------------------------------------
  task test_all_zero_s2v;
    begin : test_all_zero_s2v
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_cmac = 1;

      $display("TC: Verify the all zero input case.");

      dut_ad_start  = 16'h00a0;
      dut_ad_length = 20'h0;

      dut_nonce_start  = 16'h55aa;
      dut_nonce_length = 20'h0;

      dut_pc_start  = 16'hbeef;
      dut_pc_length = 20'h0;

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;

      $display("TC: Init and all zero handling should be done.");


      if (dut.v_reg != 128'h6a388223b4c07907611eb5f86f725597)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x6a388223b4c07907611eb5f86f725597, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - v_reg correctly set.");
      else
        $display("TC: NO SUCCESS - v_reg not correctly set.");
      $display("");
    end
  endtask // test_all_zero_s2v


  //----------------------------------------------------------------
  // test_s2v
  //
  // Test case using test vectors from RFC 5297 to verify that
  // the S2V functionality works.
  //----------------------------------------------------------------
  task test_s2v;
    begin : test_s2v
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_cmac = 1;

      // Write test vectors into the test mem.
      write_block(16'h0, 128'hdeadbeef_aa55aa55_01010101_fefefefe);
      write_block(16'h1, 128'hdeaddead_01010101_fefefefe_55aa55aa);
      read_block(16'h1);
      dump_mem(16'h0, 16'h3);

      $display("TC: Verify S2V functionality.");

      dut_ad_start  = 16'h00a0;
      dut_ad_length = 20'h0;

      dut_nonce_start  = 16'h55aa;
      dut_nonce_length = 20'h7;

      dut_pc_start  = 16'hbeef;
      dut_pc_length = 20'h99;

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;

      $display("TC: S2V processing should be completed.");


      if (dut.v_reg != 128'h6a388223b4c07907611eb5f86f725597)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x6a388223b4c07907611eb5f86f725597, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - v_reg correctly set.");
      else
        $display("TC: NO SUCCESS - v_reg not correctly set.");
      $display("");
    end
  endtask // test_s2v


  //----------------------------------------------------------------
  // main
  //
  // The main test functionality.
  //----------------------------------------------------------------
  initial
    begin : main
      $display("*** Testbench for AES_SIV_CORE started ***");
      $display("");

      init_sim();
      reset_dut();
//      test_block_bits();
//      test_all_zero_s2v();
      test_s2v();

//      tc1_reset_state();
//      tc2_s2v_init();
//      tc3_s2v_finalize_no_ad();

      display_test_results();

      $display("*** AES_SIV_CORE simulation completed. ***");
      $finish;
    end // main

endmodule // tb_aes_siv_core

//======================================================================
// EOF tb_tb_aes_siv_core.v
//======================================================================
