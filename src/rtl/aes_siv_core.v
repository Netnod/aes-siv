//======================================================================
//
// aes_siv_core.v
// --------------
// Implementation av aead_aes_siv_cmac as specified in RFC 5297:
// https://tools.ietf.org/html/rfc5297
//
// The core supports:
// AEAD_AES_SIV_CMAC_256
// AEAD_AES_SIV_CMAC_512
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

module aes_siv_core(
                    input wire            clk,
                    input wire            reset_n,

                    input wire            encdec,
                    input wire [511 : 0]  key,
                    input wire            mode,
                    input wire            start,

                    input wire [15 :0]    ad_start,
                    input wire [19 :0]    ad_length,

                    input wire [15 :0]    nonce_start,
                    input wire [19 :0]    nonce_length,

                    input wire [15 :0]    pc_start,
                    input wire [19 :0]    pc_length,

                    output wire           cs,
                    output wire           we,
                    input wire            ack,
                    output wire [15 : 0]  addr,
                    input wire [127 : 0]  block_rd,
                    output wire [127 : 0] block_wr,

                    output wire [127 : 0] tag_in,
                    output wire [127 : 0] tag_out,
                    output wire           tag_ok,
                    output wire           ready
                   );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE          = 5'h00;
  localparam CTRL_S2V_INIT      = 5'h01;
  localparam CTRL_S2V_SELECT    = 5'h02;
  localparam CTRL_S2V_AD_INIT   = 5'h03;
  localparam CTRL_S2V_AD_NEXT   = 5'h05;
  localparam CTRL_S2V_AD_FINAL  = 5'h04;
  localparam CTRL_S2V_NONCE0    = 5'h06;
  localparam CTRL_S2V_NONCE1    = 5'h07;
  localparam CTRL_S2V_NONCE2    = 5'h08;
  localparam CTRL_S2V_PC0       = 5'h09;
  localparam CTRL_S2V_PC1       = 5'h0a;
  localparam CTRL_S2V_PC2       = 5'h0b;
  localparam CTRL_S2V_FINALIZE  = 5'h0e;
  localparam CTRL_S2V_ZDONE     = 5'h0f;
  localparam CTRL_CTR_INIT0     = 5'h10;
  localparam CTRL_CTR_INIT1     = 5'h11;
  localparam CTRL_CTR_NEXT0     = 5'h12;
  localparam CTRL_CTR_NEXT1     = 5'h13;
  localparam CTRL_DONE          = 5'h1f;

  localparam AEAD_AES_SIV_CMAC_256 = 1'h0;
  localparam AEAD_AES_SIV_CMAC_512 = 1'h1;

  localparam CMAC_ZEROES = 2'h0;
  localparam CMAC_ONE    = 2'h1;
  localparam CMAC_BLOCK  = 2'h2;
  localparam CMAC_FINAL  = 2'h3;

  localparam D_CMAC = 2'h0;
  localparam D_DBL  = 2'h1;
  localparam D_XOR  = 2'h2;

  localparam ADDR_AD    = 2'h0;
  localparam ADDR_NONCE = 2'h1;
  localparam ADDR_PC    = 2'h2;

  localparam AES_BLOCK_SIZE = 128;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [127 : 0] block_reg;
  reg           block_we;

  reg [15 : 0]  addr_reg;
  reg [15 : 0]  addr_new;
  reg           addr_we;
  reg           addr_set;
  reg [1 : 0]   addr_mux;
  reg           addr_inc;

  reg           cs_reg;
  reg           cs_new;
  reg           cs_we;

  reg           we_reg;
  reg           we_new;
  reg           we_we;

  reg [15 : 0]  block_ctr_reg;
  reg [15 : 0]  block_ctr_new;
  reg           block_ctr_we;

  reg [15 :0]   ad_start_reg;
  reg [19 :0]   ad_length_reg;
  reg [15 :0]   nonce_start_reg;
  reg [19 :0]   nonce_length_reg;
  reg [15 :0]   pc_start_reg;
  reg [19 :0]   pc_length_reg;
  reg           start_len_we;

  reg [127 : 0] d_reg;
  reg [127 : 0] d_new;
  reg           d_we;

  reg [127 : 0] v_reg;
  reg           v_we;

  reg [127 : 0] x_reg;
  reg [127 : 0] x_new;
  reg           x_we;

  reg [127 : 0] result_reg;
  reg [127 : 0] result_new;
  reg           result_we;

  reg [4 : 0]   core_ctrl_reg;
  reg [4 : 0]   core_ctrl_new;
  reg           core_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            aes_encdec;
  reg            aes_init;
  reg            aes_next;
  reg [255 : 0]  aes_key;
  reg            aes_keylen;
  reg [127 : 0]  aes_block;
  wire [127 : 0] aes_result;
  wire           aes_ready;
  wire           aes_valid;

  reg [255 : 0]  cmac_key;
  reg            cmac_keylen;
  reg [7 : 0]    cmac_final_size;
  reg            cmac_init;
  reg            cmac_next;
  reg            cmac_finalize;
  reg [127 : 0]  cmac_block;
  wire [127 : 0] cmac_result;
  wire           cmac_ready;
  wire           cmac_valid;
  reg [1 : 0]    cmac_inputs;

  reg            init_ctr;
  reg            update_ctr;

  reg            s2v_init;

  reg [15 : 0]   ad_num_blocks;
  reg [7 : 0]    ad_final_size;
  reg            ad_zlen;

  reg [15 : 0]   nonce_num_blocks;
  reg [7 : 0]    nonce_final_size;
  reg            nonce_zlen;

  reg [15 : 0]   pc_num_blocks;
  reg [7 : 0]    pc_final_size;
  reg            pc_zlen;

  reg            update_d;
  reg [1 : 0]    ctrl_d;

  reg            update_v;

  reg            tmp_block_wr;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign cs       = cs_reg;
  assign we       = we_reg;
  assign addr     = addr_reg;
  assign block_wr = tmp_block_wr;
  assign ready    = ready_reg;
  assign tag_out  = v_reg;


  //----------------------------------------------------------------
  // Functions.
  //----------------------------------------------------------------
  function [127 : 0] double(input [127 : 0] op);
    begin
      if (op[127])
        double = {op[126 : 0], 1'h0} ^ 128'h87;
      else
        double = {op[126 : 0], 1'h0};
    end
  endfunction


  //----------------------------------------------------------------
  // core instantiations.
  //----------------------------------------------------------------
  // AES core is only used for CTR part.
  aes_core aes(
               .clk(clk),
               .reset_n(reset_n),

               .encdec(aes_encdec),
               .init(aes_init),
               .next(aes_next),
               .ready(aes_ready),

               .key(aes_key),
               .keylen(aes_keylen),

               .block(aes_block),
               .result(aes_result),
               .result_valid(aes_valid)
               );


  cmac_core cmac(
                 .clk(clk),
                 .reset_n(reset_n),
                 .key(cmac_key),
                 .keylen(cmac_keylen),
                 .final_size(cmac_final_size),
                 .init(cmac_init),
                 .next(cmac_next),
                 .finalize(cmac_finalize),
                 .block(cmac_block),
                 .result(cmac_result),
                 .ready(cmac_ready),
                 .valid(cmac_valid)
                );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk)
    begin: reg_update
      if (!reset_n)
        begin
          ready_reg        <= 1'h1;
          block_reg        <= 128'h0;
          result_reg       <= 128'h0;
          d_reg            <= 128'h0;
          v_reg            <= 128'h0;
          x_reg            <= 128'h0;
          addr_reg         <= 16'h0;
          cs_reg           <= 1'h0;
          we_reg           <= 1'h0;
          block_ctr_reg    <= 16'h0;
          ad_start_reg     <= 16'h0;;
          ad_length_reg    <= 20'h0;
          nonce_start_reg  <= 16'h0;;
          nonce_length_reg <= 20'h0;
          pc_start_reg     <= 16'h0;;
          pc_length_reg    <= 20'h0;
          core_ctrl_reg    <= CTRL_IDLE;
        end
      else
        begin
          if (ready_we)
            ready_reg <= ready_new;

          if (addr_we)
            addr_reg <= addr_new;

          if (cs_we)
            cs_reg <= cs_new;

          if (we_we)
            we_reg <= we_new;

          if (block_ctr_we)
            block_ctr_reg <= block_ctr_new;

          if (d_we)
            d_reg <= d_new;

          if (v_we)
            v_reg <= cmac_result;

          if (x_we)
            x_reg <= x_new;

          if (result_we)
            result_reg <= result_new;

          if (core_ctrl_we)
            core_ctrl_reg <= core_ctrl_new;

          if (start_len_we)
            begin
              ad_start_reg     <= ad_start;
              ad_length_reg    <= ad_length;
              nonce_start_reg  <= nonce_start;
              nonce_length_reg <= nonce_length;
              pc_start_reg     <= pc_start;
              pc_length_reg    <= pc_length;
            end

        end
    end // reg_update


  //----------------------------------------------------------------
  // s2v_dp
  //
  // Datapath for the S2V functionality.
  // Note that the S2V functionality assumes that the CMAC core
  // has access to the AES core.
  //----------------------------------------------------------------
  always @*
    begin : siv_cmac_dp
      d_new        = 128'h0;
      d_we         = 1'h0;
      v_we         = 1'h0;
      start_len_we = 1'h0;
      cmac_block   = 128'h0;

      cmac_key     = key[511 : 256];
      cmac_keylen  = mode;

      if (s2v_init)
        begin
          start_len_we = 1'h1;
        end // if (s2v_init)

      case (cmac_inputs)
        CMAC_ZEROES: cmac_block = 128'h0;
        CMAC_ONE:    cmac_block = 128'h1;
        CMAC_BLOCK:  cmac_block = block_rd;
        CMAC_FINAL:  cmac_block = d_reg;
      endcase // case (cmac_inputs)

      if (update_v)
        begin
          v_we  = 1'h1;
        end

      if (update_d)
        begin
          d_we = 1'h1;
          case (ctrl_d)
            D_CMAC: d_new = cmac_result;
            D_DBL:  d_new = double(d_reg);
            D_XOR:  d_new = d_reg ^ cmac_result;
            default
              begin
              end
          endcase // case (d_ctrl)
        end
    end


  //----------------------------------------------------------------
  // ctr_dp
  //
  // Datapath for the CTR functionality.
  // Note that the CTR functionality assumes that it has access
  // to the AES core.
  //----------------------------------------------------------------
  always @*
    begin : ctr_dp
      reg [63 : 0] x_tmp;

      x_new = 128'h0;
      x_we  = 1'h0;

      // Clear bit 63 and 31 when seeding the counter.
      // See RFC 5297, Section 2.5.
      if (init_ctr)
        begin
          x_new = {v_reg[127 : 64], 1'h0, v_reg[62 : 32], 1'h0, v_reg[30 : 0]};
          x_we  = 1'h1;
        end

      // 64 bit adder used.
      if (update_ctr)
        begin
          result_new = block_reg ^ aes_result;
          result_we  = 1'h1;
          x_tmp = x_reg[63 : 0] + 1'h1;
          x_new = {x_reg[127 : 64], x_tmp};
          x_we  = 1'h1;
        end
    end // ctr_dp


  //----------------------------------------------------------------
  // length_decoder
  //
  // Logic that decodes the length info for ad, nonce, pc into
  // number of blocks and number of bits in the last block. The
  // logic also detects if the length is zero.
  //----------------------------------------------------------------
  always @*
    begin : length_decoder
      ad_num_blocks    = 16'h0;
      ad_final_size    = 8'h0;
      nonce_num_blocks = 16'h0;
      nonce_final_size = 8'h0;
      pc_num_blocks    = 16'h0;
      pc_final_size    = 8'h0;


      ad_zlen    = ~|ad_length_reg;
      nonce_zlen = ~|nonce_length_reg;
      pc_zlen    = ~|pc_length_reg;

      if (!ad_zlen)
        begin
          if (ad_length_reg[3 : 0] == 4'h0)
            begin
              ad_num_blocks = ad_length[19 : 4];
              ad_final_size = 8'h80;
            end
          else
            begin
              ad_num_blocks = ad_length[19 : 4] + 1'h1;
              ad_final_size = {ad_length[3 : 0], 3'h0};
            end
        end

      if (!nonce_zlen)
        begin
          if (nonce_length_reg[3 : 0] == 4'h0)
            begin
              nonce_num_blocks = nonce_length[19 : 4];
              nonce_final_size = 8'h80;
            end
          else
            begin
              nonce_num_blocks = nonce_length[19 : 4] + 1'h1;
              nonce_final_size = {nonce_length[3 : 0], 3'h0};
            end
        end

      if (!pc_zlen)
        begin
          if (pc_length_reg[3 : 0] == 4'h0)
            begin
              pc_num_blocks = pc_length[19 : 4];
              pc_final_size = 8'h80;
            end
          else
            begin
              pc_num_blocks = pc_length[19 : 4] + 1'h1;
              pc_final_size = {pc_length[3 : 0], 3'h0};
            end
        end
    end

  //----------------------------------------------------------------
  // addr_block_ctr
  //
  // Logic for setting and updating the address generator.
  // The logic also handles resetting and updating the
  // block counter.
  //----------------------------------------------------------------
  always @*
    begin : addr_block_ctr
      addr_new      = 16'h0;
      addr_we       = 1'h0;
      block_ctr_new = 16'h0;
      block_ctr_we  = 1'h0;

      if (addr_set)
        begin
          addr_we = 1'h1;
          case (addr_mux)
            ADDR_AD: addr_new    = ad_start_reg;
            ADDR_NONCE: addr_new = nonce_start_reg;
            ADDR_PC: addr_new    = pc_start_reg;
          endcase // case (addr_mux)

          block_ctr_new = 16'h0;
          block_ctr_we  = 1'h1;
        end

      if (addr_inc)
        begin
          addr_new = addr_reg + 1'h1;
          addr_we  = 1'h1;

          block_ctr_new = block_ctr_reg + 1'h1;
          block_ctr_we  = 1'h1;
        end
    end


  //----------------------------------------------------------------
  // core_ctrl
  //----------------------------------------------------------------
  always @*
    begin : core_ctrl
      ready_new       = 1'h0;
      ready_we        = 1'h0;
      cmac_final_size = 8'h0;
      cmac_init       = 1'h0;
      cmac_next       = 1'h0;
      cmac_finalize   = 1'h0;
      addr_set        = 1'h0;
      addr_mux        = ADDR_AD;
      addr_inc        = 1'h0;
      s2v_init        = 1'h0;
      init_ctr        = 1'h0;
      update_ctr      = 1'h0;
      result_new      = 128'h0;
      result_we       = 1'h0;
      cmac_inputs     = CMAC_ZEROES;
      update_d        = 1'h0;
      ctrl_d          = D_CMAC;
      update_v        = 1'h0;
      cs_new          = 1'h0;
      cs_we           = 1'h0;
      we_new          = 1'h0;
      we_we           = 1'h0;
      tmp_block_wr    = 128'h0;
      core_ctrl_new   = CTRL_IDLE;
      core_ctrl_we    = 1'h0;

      case (core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (start)
              begin
                ready_new     = 1'h0;
                ready_we      = 1'h1;
                s2v_init      = 1'h1;
                cmac_init     = 1'h1;
                core_ctrl_new = CTRL_S2V_INIT;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_S2V_INIT:
          begin
            if (cmac_ready)
              begin
                if (ad_zlen & nonce_zlen & pc_zlen)
                  begin
                    cmac_inputs     = CMAC_ONE;
                    cmac_final_size = AES_BLOCK_SIZE;
                    cmac_finalize   = 1'h1;
                    core_ctrl_new   = CTRL_S2V_ZDONE;
                    core_ctrl_we    = 1'h1;
                  end
                else
                  begin
                    cmac_inputs     = CMAC_ZEROES;
                    cmac_final_size = AES_BLOCK_SIZE;
                    cmac_finalize   = 1'h1;
                    core_ctrl_new   = CTRL_S2V_SELECT;
                    core_ctrl_we    = 1'h1;
                  end
              end
          end


        CTRL_S2V_SELECT:
          begin
            if (cmac_ready)
              begin
                update_d  = 1'h1;
                ctrl_d    = D_CMAC;
                cmac_init = 1'h1;

                if (!ad_zlen)
                  begin
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_AD;
                    cs_new        = 1'h1;
                    cs_we         = 1'h1;
                    core_ctrl_new = CTRL_S2V_AD_INIT;
                    core_ctrl_we  = 1'h1;
                  end

                else if (!nonce_zlen)
                  begin
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_NONCE;
                    core_ctrl_new = CTRL_S2V_NONCE0;
                    core_ctrl_we  = 1'h1;
                  end

                else
                  begin
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_PC;
                    core_ctrl_new = CTRL_S2V_PC0;
                    core_ctrl_we  = 1'h1;
                  end
              end
          end


        // Wait for cmac to be ready.
        // Check that we got the first block.
        CTRL_S2V_AD_INIT:
          begin
            if (cmac_ready)
              begin
                if (ack)
                  begin
                    cs_new = 1'h0;
                    cs_we  = 1'h1;

                    if (ad_num_blocks == 16'h1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = ad_final_size;
                        cmac_finalize   = 1'h1;
                        core_ctrl_new   = CTRL_S2V_AD_FINAL;
                        core_ctrl_we    = 1'h1;
                      end
                    else
                      begin
                        cmac_next     = 1'h1;
                        cmac_inputs   = CMAC_BLOCK;
                        addr_inc      = 1'h1;
                        cs_new        = 1'h1;
                        cs_we         = 1'h1;
                        core_ctrl_new = CTRL_S2V_AD_NEXT;
                        core_ctrl_we  = 1'h1;
                      end
                  end
              end
          end


        // Wait for cmac to be ready.
        // Check that we got the next block.
        CTRL_S2V_AD_NEXT:
          begin
            if (cmac_ready)
              begin
                if (ack)
                  begin
                    cs_new = 1'h0;
                    cs_we  = 1'h1;

                    if (block_ctr_reg == ad_num_blocks - 1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_finalize   = 1'h1;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = ad_final_size;
                        core_ctrl_new   = CTRL_S2V_AD_FINAL;
                        core_ctrl_we    = 1'h1;
                      end
                    else
                      begin
                        cmac_next     = 1'h1;
                        cmac_inputs   = CMAC_BLOCK;
                        addr_inc      = 1'h1;
                        cs_new        = 1'h1;
                        cs_we         = 1'h1;
                      end
                  end
              end
          end


        CTRL_S2V_AD_FINAL:
          begin
            if (cmac_ready)
              begin
                update_d      = 1'h1;
                ctrl_d        = D_XOR;
                core_ctrl_new = CTRL_DONE;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_S2V_NONCE0:
          begin
            ready_new     = 1'h1;
            ready_we      = 1'h1;
            core_ctrl_new = CTRL_IDLE;
            core_ctrl_we  = 1'h1;
          end


        CTRL_S2V_PC0:
          begin
            ready_new     = 1'h1;
            ready_we      = 1'h1;
            core_ctrl_new = CTRL_IDLE;
            core_ctrl_we  = 1'h1;
          end


        // Handle the case when all inputs to S2V
        // have zero length.
        CTRL_S2V_ZDONE:
          begin
            cmac_inputs     = CMAC_ONE;
            cmac_final_size = AES_BLOCK_SIZE;

            if (cmac_ready)
              begin
                update_v      = 1'h1;
                ready_new     = 1'h1;
                ready_we      = 1'h1;
                core_ctrl_new = CTRL_IDLE;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_INIT0:
          begin
            init_ctr      = 1'h1;
            core_ctrl_new = CTRL_CTR_INIT1;
            core_ctrl_we  = 1'h1;
          end


        CTRL_CTR_INIT1:
          begin
            if (aes_ready)
              begin
                ready_new     = 1'h1;
                ready_we      = 1'h1;
                core_ctrl_new = CTRL_IDLE;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_NEXT0:
          begin
            core_ctrl_new = CTRL_CTR_NEXT1;
            core_ctrl_we  = 1'h1;
          end


        CTRL_CTR_NEXT1:
          begin
            if (aes_ready)
              begin
                update_ctr    = 1'h1;
                result_we     = 1'h1;
                ready_new     = 1'h1;
                ready_we      = 1'h1;
                core_ctrl_new = CTRL_IDLE;
                core_ctrl_we  = 1'h1;
              end
          end

        CTRL_DONE:
          begin
            ready_new     = 1'h1;
            ready_we      = 1'h1;
            core_ctrl_new = CTRL_IDLE;
            core_ctrl_we  = 1'h1;
          end

        default:
          begin

          end
      endcase // case (core_ctrl_reg)
    end // block: core_ctrl
endmodule // aes_siv_core

//======================================================================
// EOF aes_siv_core.v
//======================================================================
