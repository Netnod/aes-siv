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
  reg [127 : 0]  dut_tag_in;
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
      $display("cs: 0x%01x, we: 0x%01x, ack: 0x%01x, addr: 0x%04x",
               dut.cs, dut.we, dut.ack, dut.addr);
      $display("block_rd: 0x%032x, block_wr: 0x%032x",
               dut.block_rd, dut.block_wr);
      $display("");

      if (show_aes)
        begin
          $display("AES:");
          $display("aes_ready: 0x%01x, aes_init: 0x%01x, aes_next: 0x%01x",
                   dut.aes_ready, dut.aes_init, dut.aes_next);
          $display("aes_keylen: 0x%01x, aes_key: 0x%032x", dut.aes_keylen, dut.aes_key);
          $display("aes_block: 0x%016x, aes_result: 0x%016x", dut.aes_block, dut.aes_result);
          $display("x_reg: 0x%016x, x_new: 0x%016x, x_we: 0x%01x",
                   dut.x_reg, dut.x_new, dut.x_we);
          $display("");
        end


      if (show_cmac)
        begin
          $display("CMAC:");
          $display("cmac_inputs: 0x%01x", dut.cmac_inputs);
          $display("cmac_ready: 0x%01x, cmac_init: 0x%01x, cmac_next: 0x%01x, cmac_finalize: 0x%01x, cmac_final_length: 0x%02x",
                   dut.cmac_ready, dut.cmac_init, dut.cmac_next, dut.cmac_finalize, dut.cmac_final_size);
          $display("cmac_keylen: 0x%01x, cmac_key: 0x%032x", dut.cmac_keylen, dut.cmac_key);
          $display("cmac_block: 0x%016x, cmac_result: 0x%016x", dut.cmac_block, dut.cmac_result);
          $display("");
        end


      if (show_s2v)
        begin
          $display("ad_start: 0x%08x, ad_length: 0x%08x, ad_zlen: 0x%01x, ad_num_blocks: 0x%08x, ad_final_size: 0x%08x",
                   dut.ad_start, dut.ad_length, dut.ad_zlen, dut.ad_num_blocks, dut.ad_final_size);
          $display("nonce_start: 0x%04x, nonce_length: 0x%06x, nonce_zlen: 0x%01x, nonce_num_blocks: 0x%04x, nonce_final_size: 0x%04x",
                   dut.nonce_start, dut.nonce_length, dut.nonce_zlen, dut.nonce_num_blocks, dut.nonce_final_size);
          $display("pc_start: 0x%08x, pc_length: 0x%08x, pc_zlen: 0x%01x, pc_num_blocks: 0x%08x, pc_final_size: 0x%08x",
                   dut.pc_start, dut.pc_length, dut.pc_zlen, dut.pc_num_blocks, dut.pc_final_size);
          $display("d_reg: 0x%016x, d_new: 0x%016x, d_we: 0x%01x",
                   dut.d_reg, dut.d_new, dut.d_we);
          $display("v_reg: 0x%016x, v_we: 0x%01x",
                   dut.v_reg, dut.v_we);
          $display("select: 0x%02x, xordend0: 0x%016x, xordend1: 0x%016x",
                   dut.pc_length[3 : 0], dut.s2v_dp.xorend0, dut.s2v_dp.xorend1);
          $display("padded_block: 0x%016x", dut.s2v_dp.padded_block);
          $display("update_block: 0x%01x, block_mux: 0x%01x, block_we: 0x%01x",
                   dut.update_block, dut.block_mux, dut.block_we);
          $display("block_reg: 0x%016x, block_new: 0x%016x, block_we: 0x%01x",
                   dut.block_reg, dut.block_new, dut.block_we);
          $display("result_reg: 0x%016x, result_new: 0x%016x, result_we: 0x%01x",
                   dut.result_reg, dut.result_new, dut.result_we);
          $display("");
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

      dut_encdec = 1'h1;

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
  // test_s2v_A1
  //
  // Test case using test vectors from RFC 5297, A.1 to verify
  // that the S2V functionality works.
  //----------------------------------------------------------------
  task test_s2v_A1;
    begin : test_s2v_A1
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_aes  = 1;
      show_cmac = 1;

      $display("test_s2v_A1: Verify S2V functionality.");

      // Write test vectors into the test mem.
      // Writing test vectors from RFC 5297, Appendix A.1
      // Deterministic Authenticated Encryption Example

      // AD: 6 * 4 bytes: 24 bytes in length
      write_block(16'h0000, 128'h10111213_14151617_18191a1b_1c1d1e1f);
      write_block(16'h0001, 128'h20212223_24252627_00000000_00000000);
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h18;

      // Nonce: 0 bytes. Ignored
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h0;

      // Plaintext: 10 bytes.
      write_block(16'h0020, 128'h11223344_55667788_99aabbcc_ddee0000);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h0e;

      dump_mem(16'h0, 16'h22);

      dut_key = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0,
                 128'h0,
                 128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff,
                 128'h0};
      dut_mode = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h1;

      $display("TC: S2V processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_aes  = 0;
      show_cmac = 0;

      $display("TC: S2V processing should be completed.");

      dump_mem(16'h0, 16'h22);

      if (dut.v_reg != 128'h85632d07_c6e8f37f_950acd32_0a2ecc93)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x85632d07_c6e8f37f_950acd32_0a2ecc93, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end


      if (mem.mem[16'h0020] != 128'h40c02b96_90c4dc04_daef7f6a_fe5c0000)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x40c02b96_90c4dc04_daef7f6a_fe5c0000, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - Tag and ciphertext correct.");
      else
        $display("TC: NO SUCCESS - Tag and ciphertext NOT correct.");
      $display("");
    end
  endtask // test_s2v_A1


  //----------------------------------------------------------------
  // test_s2v_A1_mod1
  //
  // Test case using test vectors from RFC 5297, A.1 to verify
  // that the SIV Encrypt functionality works. This case is
  // modified to have no AD, but instead a nonce field.
  //----------------------------------------------------------------
  task test_s2v_A1_mod1;
    begin : test_s2v_A1_mod1
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_cmac = 1;

      $display("test_s2v_A1_mod1: Verify S2V functionality.");

      // Write test vectors into the test mem.
      // Writing test vectors from RFC 5297, Appendix A.1
      // Deterministic Authenticated Encryption Example

      // AD: 0 bytes. Should be ignored.
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h0;

      // Nonce: 24 bytes.
      write_block(16'h0010, 128'h10111213_14151617_18191a1b_1c1d1e1f);
      write_block(16'h0011, 128'h20212223_24252627_00000000_00000000);
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h18;

      // Plaintext: 10 bytes.
      write_block(16'h0020, 128'h11223344_55667788_99aabbcc_ddee0000);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h0e;

      dump_mem(16'h0, 16'h22);

      dut_key = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0,
                 128'h0,
                 128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff,
                 128'h0};

      dut_mode   = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h1;

      $display("TC: S2V processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;

      $display("TC: S2V processing should be completed.");

      dump_mem(16'h0, 16'h22);

      if (dut.v_reg != 128'h85632d07_c6e8f37f_950acd32_0a2ecc93)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x85632d07_c6e8f37f_950acd32_0a2ecc93, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end


      if (mem.mem[16'h0020] != 128'h40c02b96_90c4dc04_daef7f6a_fe5c0000)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x40c02b96_90c4dc04_daef7f6a_fe5c0000, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - Tag and ciphertext correct.");
      else
        $display("TC: NO SUCCESS - Tag and ciphertext NOT correct.");
      $display("");
    end
  endtask // test_s2v_A1_mod1


  //----------------------------------------------------------------
  // test_s2v_A2_mod1
  //
  // Test case using test vectors from RFC 5297, A.2 but modified
  // to only have one AD field. Expected results:
  // Tag: 85825e22 e90cf2dd da2c548d c7c1b631
  // C:   0dcdaca0 cebf9dc6 cb90583f 5bf1506e 02cd4883 2b00e4e5
  //      98b2b22a 53e6199d 4df0c166 6a35a043 3b250dc1 34d776
  //
  // Expected partial results:
  //    CMAC(zero): c8b43b59 74960e7c e6a5dd85 231e591a
  //      double(): 916876b2 e92c1cf9 cd4bbb0a 463cb2b3
  //      CMAC(ad): 3c9b689a b41102e4 80954714 1dd0d15a
  //           xor: adf31e28 5d3d1e1d 4ddefc1e 5bec63e9
  //      double(): 5be63c50 ba7a3c3a 9bbdf83c b7d8c755
  //      CMAC(ad): 128c62a1 ce3747a8 372c1c05 a538b96d
  //           xor: 496a5ef1 744d7b92 ac91e439 12e07e38
  // Xorend part 1: 74686973 20697320 736f6d65 20706c61
  //                696e7465 78742074 6f20656e 63727939
  // xorend part 2: 1e7e8407 2415f58c c2ad6f3f a13b6b
  //   CMAC(final): 85825e22 e90cf2dd da2c548d c7c1b631
  //    ciphertext: 0dcdaca0 cebf9dc6 cb90583f 5bf1506e
  //                02cd4883 2b00e4e5 98b2b22a 53e6199d
  //                4df0c166 6a35a043 3b250dc1 34d776
  //       IV || C: 85825e22 e90cf2dd da2c548d c7c1b631
  //                0dcdaca0 cebf9dc6 cb90583f 5bf1506e
  //                02cd4883 2b00e4e5 98b2b22a 53e6199d
  //                4df0c166 6a35a043 3b250dc1 34d776
  //----------------------------------------------------------------
  task test_s2v_A2_mod1;
    begin : test_s2v_A2_mod1
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;
      show_aes  = 0;

      $display("test_s2v_A2_mod1: Verify S2V functionality.");

      // AD: 10 * 4 bytes: 40 bytes in length.
      write_block(16'h0000, 128'h00112233_44556677_8899aabb_ccddeeff);
      write_block(16'h0001, 128'hdeaddada_deaddada_ffeeddcc_bbaa9988);
      write_block(16'h0002, 128'h77665544_33221100_00000000_00000000);
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h28;

      // Nonce: 16.
      write_block(16'h0010, 128'h09f91102_9d74e35b_d84156c5_635688c0);
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h10;

      // Plaintext: 47 bytes.
      write_block(16'h0020, 128'h74686973_20697320_736f6d65_20706c61);
      write_block(16'h0021, 128'h696e7465_78742074_6f20656e_63727970);
      write_block(16'h0022, 128'h74207573_696e6720_5349562d_41455300);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h2f;

      dump_mem(16'h0, 16'h24);

      dut_key = {128'h7f7e7d7c_7b7a7978_77767574_73727170,
                 128'h0,
                 128'h40414243_44454647_48494a4b_4c4d4e4f,
                 128'h0};
      dut_mode = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h1;

      $display("TC: S2V processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;
      show_aes  = 0;

      $display("TC: S2V processing should be completed.");

      dump_mem(16'h0, 16'h24);


      // Check the generated tag.
      if (dut.v_reg != 128'h85825e22_e90cf2dd_da2c548d_c7c1b631)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x85825e22_e90cf2dd_da2c548d_c7c1b631, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      // Check the generated ciphertext.
      if (mem.mem[16'h0020] != 128'h0dcdaca0cebf9dc6cb90583f5bf1506e)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x0dcdaca0_cebf9dc6_cb90583f_5bf1506e, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      // Check the generated ciphertext.
      if (mem.mem[16'h0021] != 128'h02cd48832b00e4e598b2b22a53e6199d)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x02cd488_32b00e4_e598b2b2_2a53e6199d, got 0x%032x.",
                   mem.mem[16'h0021]);
          tc_correct = 0;
          inc_error_ctr();
        end

      // Check the generated ciphertext.
      if (mem.mem[16'h0022] != 128'h4df0c1666a35a0433b250dc134d77600)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x4df0c16_66a35a04_33b250dc_134d77600, got 0x%032x.",
                   mem.mem[16'h0022]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - tag and cipher text correctly generated.");
      else
        $display("TC: NO SUCCESS - tag and cipher text not correctly generated.");
      $display("");
    end
  endtask // test_s2v_A2_mod1


  //----------------------------------------------------------------
  // test_s2v_A2_mod2
  //
  // Test case using test vectors from RFC 5297, A.2 but modified
  // to only have a plaintext field with zero length.
  // Expected results:
  // Tag: 4cf1e6f9 180dca76 83caaa9c 7bb70ec6
  //
  // Expected partial results:
  //     CMAC(zero): c8b43b59 74960e7c e6a5dd85 231e591a
  //       double(): 916876b2 e92c1cf9 cd4bbb0a 463cb2b3
  //       CMAC(ad): 3c9b689a b41102e4 80954714 1dd0d15a
  //            xor: adf31e28 5d3d1e1d 4ddefc1e 5bec63e9
  //       double(): 5be63c50 ba7a3c3a 9bbdf83c b7d8c755
  //       CMAC(ad): 128c62a1 ce3747a8 372c1c05 a538b96d
  //            xor: 496a5ef1 744d7b92 ac91e439 12e07e38
  //            Pad: 80000000 00000000 00000000 00000000
  //            xor: 12d4bde2 e89af725 5923c872 25c0fc70
  //    CMAC(final): 4cf1e6f9 180dca76 83caaa9c 7bb70ec6
  //     ciphertext:
  //        IV || C: 4cf1e6f9 180dca76 83caaa9c 7bb70ec6
  //
  //----------------------------------------------------------------
  task test_s2v_A2_mod2;
    begin : test_s2v_A2_mod2
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_cmac = 1;

      $display("test_s2v_A2_mod2: Verify S2V functionality.");

      // AD: 10 * 4 bytes: 40 bytes in length.
      write_block(16'h0000, 128'h00112233_44556677_8899aabb_ccddeeff);
      write_block(16'h0001, 128'hdeaddada_deaddada_ffeeddcc_bbaa9988);
      write_block(16'h0002, 128'h77665544_33221100_00000000_00000000);
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h28;

      // Nonce: 16.
      write_block(16'h0010, 128'h09f91102_9d74e35b_d84156c5_635688c0);
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h10;

      // Zero length plaintext.
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h00;

      dump_mem(16'h0, 16'h24);

      dut_key = {128'h7f7e7d7c_7b7a7978_77767574_73727170,
                 128'h0,
                 128'h40414243_44454647_48494a4b_4c4d4e4f,
                 128'h0};
      dut_mode = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h1;

      $display("TC: S2V processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;

      $display("TC: S2V processing should be completed.");


      if (dut.v_reg != 128'h4cf1e6f9_180dca76_83caaa9c_7bb70ec6)
        begin
          $display("TC: ERROR - v_reg incorrect. Expected 0x4cf1e6f9_180dca76_83caaa9c_7bb70ec6, got 0x%032x.", dut.v_reg);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - v_reg correctly set.");
      else
        $display("TC: NO SUCCESS - v_reg not correctly set.");
      $display("");
    end
  endtask // test_s2v_A2_mod2



  //----------------------------------------------------------------
  // test_s2v_A1_decrypt
  //
  // Test case using test vectors from RFC 5297, A.1 to verify
  // that the SIV Decrypt functionality works.
  //----------------------------------------------------------------
  task test_s2v_A1_decrypt;
    begin : test_s2v_A1
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_aes  = 1;
      show_cmac = 1;

      $display("test_s2v_A1_decrypt: Verify SIV-Decrypt functionality.");

      // Write test vectors into the test mem.
      // Writing test vectors from RFC 5297, Appendix A.1
      // Deterministic Authenticated Decryption Example

      // AD: 6 * 4 bytes: 24 bytes in length
      write_block(16'h0000, 128'h10111213_14151617_18191a1b_1c1d1e1f);
      write_block(16'h0001, 128'h20212223_24252627_00000000_00000000);
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h18;

      // Nonce: 0 bytes. Ignored
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h0;

      // Ciphertext: 10 bytes.
      write_block(16'h0020, 128'h40c02b96_90c4dc04_daef7f6a_fe5c0000);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h0e;

      dump_mem(16'h0, 16'h22);

      dut_key = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0,
                 128'h0,
                 128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff,
                 128'h0};

      dut_mode   = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h0;
      dut_tag_in = 128'h85632d07_c6e8f37f_950acd32_0a2ecc93;


      $display("TC: SIV Decrypt processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_aes  = 0;
      show_cmac = 0;

      $display("TC: SIV Decrypt processing should be completed.");

      dump_mem(16'h0, 16'h22);

      if (!dut_tag_ok)
        begin
          $display("TC: ERROR - Generated tag did not match generated tag.");
          tc_correct = 0;
          inc_error_ctr();
        end


      if (mem.mem[16'h0020] != 128'h11223344_55667788_99aabbcc_ddee0000)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x11223344_55667788_99aabbcc_ddee0000, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - Tag and plaintext correct.");
      else
        $display("TC: NO SUCCESS - Tag and plaintext NOT correct.");
      $display("");
    end
  endtask // test_s2v_A1_decrypt


  //----------------------------------------------------------------
  // test_s2v_A1_mod1_decrypt
  //
  // Test case using test vectors from RFC 5297, A.1 to verify
  // that the SIV Decrypt functionality works. This case is
  // modified to have no AD, but instead a nonce field.
  //----------------------------------------------------------------
  task test_s2v_A1_mod1_decrypt;
    begin : test_s2v_A1_mod1_decrypt
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 1;
      show_s2v  = 1;
      show_cmac = 1;

      $display("test_s2v_A1_mod1_decrypt: Verify SIV Decrypt functionality.");

      // Write test vectors into the test mem.
      // Writing test vectors from RFC 5297, Appendix A.1
      // Deterministic Authenticated Encryption Example

      // AD: 0 bytes. Should be ignored.
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h0;

      // Nonce: 24 bytes.
      write_block(16'h0010, 128'h10111213_14151617_18191a1b_1c1d1e1f);
      write_block(16'h0011, 128'h20212223_24252627_00000000_00000000);
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h18;

      // Ciphertext Plaintext: 10 bytes.
      write_block(16'h0020, 128'h40c02b96_90c4dc04_daef7f6a_fe5c0000);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h0e;

      dump_mem(16'h0, 16'h22);

      dut_key = {128'hfffefdfc_fbfaf9f8_f7f6f5f4_f3f2f1f0,
                 128'h0,
                 128'hf0f1f2f3_f4f5f6f7_f8f9fafb_fcfdfeff,
                 128'h0};

      dut_mode   = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h0;

      $display("TC: SIV Decrypt processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;

      $display("TC: SIV Decrypt processing should be completed.");

      dump_mem(16'h0, 16'h22);

      if (!dut_tag_ok)
        begin
          $display("TC: ERROR - Generated tag did not match generated tag.");
          tc_correct = 0;
          inc_error_ctr();
        end

      if (mem.mem[16'h0020] != 128'h11223344_55667788_99aabbcc_ddee0000)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x11223344_55667788_99aabbcc_ddee0000, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - Tag and plaintext correct.");
      else
        $display("TC: NO SUCCESS - Tag and plaintext NOT correct.");
      $display("");
    end
  endtask // test_s2v_A1_mod1_decrypt


  //----------------------------------------------------------------
  // test_s2v_A2_mod1_decrypt
  //
  // Test case using test vectors from RFC 5297, A.2 but modified
  // to only have one AD field. Expected results:
  // Tag: 85825e22 e90cf2dd da2c548d c7c1b631
  // C:   0dcdaca0 cebf9dc6 cb90583f 5bf1506e 02cd4883 2b00e4e5
  //      98b2b22a 53e6199d 4df0c166 6a35a043 3b250dc1 34d776
  //
  // Expected partial results:
  //    CMAC(zero): c8b43b59 74960e7c e6a5dd85 231e591a
  //      double(): 916876b2 e92c1cf9 cd4bbb0a 463cb2b3
  //      CMAC(ad): 3c9b689a b41102e4 80954714 1dd0d15a
  //           xor: adf31e28 5d3d1e1d 4ddefc1e 5bec63e9
  //      double(): 5be63c50 ba7a3c3a 9bbdf83c b7d8c755
  //      CMAC(ad): 128c62a1 ce3747a8 372c1c05 a538b96d
  //           xor: 496a5ef1 744d7b92 ac91e439 12e07e38
  // Xorend part 1: 74686973 20697320 736f6d65 20706c61
  //                696e7465 78742074 6f20656e 63727939
  // xorend part 2: 1e7e8407 2415f58c c2ad6f3f a13b6b
  //   CMAC(final): 85825e22 e90cf2dd da2c548d c7c1b631
  //    ciphertext: 0dcdaca0 cebf9dc6 cb90583f 5bf1506e
  //                02cd4883 2b00e4e5 98b2b22a 53e6199d
  //                4df0c166 6a35a043 3b250dc1 34d776
  //       IV || C: 85825e22 e90cf2dd da2c548d c7c1b631
  //                0dcdaca0 cebf9dc6 cb90583f 5bf1506e
  //                02cd4883 2b00e4e5 98b2b22a 53e6199d
  //                4df0c166 6a35a043 3b250dc1 34d776
  //----------------------------------------------------------------
  task test_s2v_A2_mod1_decrypt;
    begin : test_s2v_A2_mod1_decrypt
      inc_tc_ctr();
      tc_correct = 1;

      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;
      show_aes  = 0;

      $display("test_s2v_A2_mod1_decrypt: Verify SIV Decrypt functionality.");

      // AD: 10 * 4 bytes: 40 bytes in length.
      write_block(16'h0000, 128'h00112233_44556677_8899aabb_ccddeeff);
      write_block(16'h0001, 128'hdeaddada_deaddada_ffeeddcc_bbaa9988);
      write_block(16'h0002, 128'h77665544_33221100_00000000_00000000);
      dut_ad_start  = 16'h0000;
      dut_ad_length = 20'h28;

      // Nonce: 16.
      write_block(16'h0010, 128'h09f91102_9d74e35b_d84156c5_635688c0);
      dut_nonce_start  = 16'h0010;
      dut_nonce_length = 20'h10;

      // Ciphertext: 47 bytes.
      write_block(16'h0020, 128'h0dcdaca0_cebf9dc6_cb90583f_5bf1506e);
      write_block(16'h0021, 128'h02cd4883_2b00e4e5_98b2b22a_53e6199d);
      write_block(16'h0022, 128'h4df0c166_6a35a043_3b250dc1_34d77600);
      dut_pc_start  = 16'h0020;
      dut_pc_length = 20'h2f;

      dump_mem(16'h0, 16'h24);

      dut_key = {128'h7f7e7d7c_7b7a7978_77767574_73727170,
                 128'h0,
                 128'h40414243_44454647_48494a4b_4c4d4e4f,
                 128'h0};

      dut_mode   = AEAD_AES_SIV_CMAC_256;
      dut_encdec = 1'h0;
      dut_tag_in = 128'h85825e22_e90cf2dd_da2c548d_c7c1b631;

      $display("TC: SIV Decypt processing started.");

      dut_start = 1'h1;
      #(CLK_PERIOD);
      dut_start = 1'h0;

      wait_ready();
      #(2 * CLK_PERIOD);
      debug_dut = 0;
      show_s2v  = 0;
      show_cmac = 0;
      show_aes  = 0;

      $display("TC: SIV Decrypt processing should be completed.");

      dump_mem(16'h0, 16'h24);


      if (!dut_tag_ok)
        begin
          $display("TC: ERROR - Generated tag did not match generated tag.");
          tc_correct = 0;
          inc_error_ctr();
        end

      if (mem.mem[16'h0020] != 128'h74686973_20697320_736f6d65_20706c61)
        begin
          $display("TC: ERROR - ciphertext incorrect. Expected 0x74686973_20697320_736f6d65_20706c61, got 0x%032x.",
                   mem.mem[16'h0020]);
          tc_correct = 0;
          inc_error_ctr();
        end

      if (tc_correct)
        $display("TC: SUCCESS - Tag and plaintext correct.");
      else
        $display("TC: NO SUCCESS - Tag and plaintext NOT correct.");
      $display("");
    end
  endtask // test_s2v_A2_mod1_decrypt


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

      // S2V and SIV-Encrypt test cases.
//      test_all_zero_s2v();
//      test_s2v_A1();
//      test_s2v_A1_mod1();
//      test_s2v_A2_mod1();
//      test_s2v_A2_mod2();

      // SIV-Decrypt test cases.
//      test_s2v_A1_decrypt();
//      test_s2v_A1_mod1_decrypt();
      test_s2v_A2_mod1_decrypt();

      display_test_results();

      $display("*** AES_SIV_CORE simulation completed. ***");
      $finish;
    end // main

endmodule // tb_aes_siv_core

//======================================================================
// EOF tb_tb_aes_siv_core.v
//======================================================================
