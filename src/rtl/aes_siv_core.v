//======================================================================
//
// aes_siv_core.v
// --------------
// Implementation av aead_aes_siv_cmac as specified in RFC 5297:
// https://tools.ietf.org/html/rfc5297
//
//
// Author: Joachim Strombergson
//
//
// Copyright 2019 Netnod Internet Exchange i Sverige AB
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
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
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

                    input wire [127 : 0]  tag_in,
                    output wire [127 : 0] tag_out,
                    output wire           tag_ok,
                    output wire           ready
                   );


  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam CTRL_IDLE            = 5'h00;
  localparam CTRL_S2V_INIT        = 5'h01;
  localparam CTRL_S2V_SELECT      = 5'h02;
  localparam CTRL_S2V_AD_INIT     = 5'h03;
  localparam CTRL_S2V_AD_NEXT     = 5'h04;
  localparam CTRL_S2V_AD_FINAL    = 5'h05;
  localparam CTRL_S2V_NONCE_INIT  = 5'h06;
  localparam CTRL_S2V_NONCE_NEXT  = 5'h07;
  localparam CTRL_S2V_NONCE_FINAL = 5'h08;
  localparam CTRL_S2V_PC_INIT     = 5'h09;
  localparam CTRL_S2V_PC_NEXT0    = 5'h0a;
  localparam CTRL_S2V_PC_NEXT1    = 5'h0b;
  localparam CTRL_S2V_PC_FINAL0   = 5'h0c;
  localparam CTRL_S2V_PC_FINAL1   = 5'h0d;
  localparam CTRL_S2V_PC_FINAL2   = 5'h0e;
  localparam CTRL_S2V_FINALIZE    = 5'h0f;
  localparam CTRL_S2V_ZDONE       = 5'h10;

  localparam CTRL_CTR_INIT        = 5'h12;
  localparam CTRL_CTR_NEXT        = 5'h13;
  localparam CTRL_CTR_READ        = 5'h14;
  localparam CTRL_CTR_RACK        = 5'h15;
  localparam CTRL_CTR_XOR         = 5'h16;
  localparam CTRL_CTR_WRITE       = 5'h17;
  localparam CTRL_CTR_WACK        = 5'h18;

  localparam CTRL_DONE            = 5'h1f;

  localparam AEAD_AES_SIV_CMAC_256 = 1'h0;
  localparam AEAD_AES_SIV_CMAC_512 = 1'h1;

  localparam CMAC_ZEROES  = 3'h0;
  localparam CMAC_ONE     = 3'h1;
  localparam CMAC_BLOCK   = 3'h2;
  localparam CMAC_XOREND0 = 3'h3;
  localparam CMAC_XOREND1 = 3'h4;
  localparam CMAC_PAD     = 3'h5;
  localparam CMAC_PAD_XOR = 3'h6;
  localparam CMAC_FINAL   = 3'h7;

  localparam D_CMAC = 2'h0;
  localparam D_DBL  = 2'h1;
  localparam D_XOR  = 2'h2;

  localparam BLOCK_DATA    = 3'h0;
  localparam BLOCK_XOR     = 3'h1;
  localparam BLOCK_XOR_PAD = 3'h2;
  localparam BLOCK_XOREND0 = 3'h3;
  localparam BLOCK_XOREND1 = 3'h4;

  localparam ADDR_AD    = 2'h0;
  localparam ADDR_NONCE = 2'h1;
  localparam ADDR_PC    = 2'h2;

  localparam AES_BLOCK_SIZE = 128;

  localparam ECB_MODE  = 1'h0;
  localparam CMAC_MODE = 1'h1;


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg           ready_reg;
  reg           ready_new;
  reg           ready_we;

  reg [127 : 0] block_reg;
  reg [127 : 0] block_new;
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

  reg [15 : 0]  ad_num_blocks_reg;
  reg [15 : 0]  ad_num_blocks_new;
  reg [7 : 0]   ad_final_size_reg;
  reg [7 : 0]   ad_final_size_new;

  reg [15 : 0]  nonce_num_blocks_reg;
  reg [15 : 0]  nonce_num_blocks_new;
  reg [7 : 0]   nonce_final_size_reg;
  reg [7 : 0]   nonce_final_size_new;

  reg [15 : 0]  pc_num_blocks_reg;
  reg [15 : 0]  pc_num_blocks_new;
  reg [7 : 0]   pc_final_size_reg;
  reg [7 : 0]   pc_final_size_new;

  reg [4 : 0]   core_ctrl_reg;
  reg [4 : 0]   core_ctrl_new;
  reg           core_ctrl_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            aes_next;
  reg [255 : 0]  aes_key;
  reg            aes_keylen;
  reg [127 : 0]  aes_block;
  wire [127 : 0] aes_result;
  wire           aes_ready;

  reg [255 : 0]  cmac_key;
  reg            cmac_keylen;
  reg [7 : 0]    cmac_final_size;
  reg            cmac_init;
  reg            cmac_next;
  reg            cmac_finalize;
  reg [127 : 0]  cmac_block;
  wire [127 : 0] cmac_result;
  wire           cmac_ready;
  reg [2 : 0]    cmac_inputs;

  reg            init_ctr;
  reg            update_ctr;

  reg            s2v_init;

  reg            ad_zlen;
  reg            nonce_zlen;
  reg            pc_zlen;

  reg            final_wr_block;

  reg            update_d;
  reg [1 : 0]    ctrl_d;

  reg            update_v;
  reg            update_block;
  reg [2 : 0]    block_mux;

  reg            cipher_mode;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign cs       = cs_reg;
  assign we       = we_reg;
  assign addr     = addr_reg;
  assign block_wr = result_reg;
  assign ready    = ready_reg;
  assign tag_out  = v_reg;
  assign tag_ok   = ~|(tag_in ^ v_reg);


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
  cmac_core cmac(
                 .clk(clk),
                 .reset_n(reset_n),

                 .cipher_mode(cipher_mode),

                 .ecb_next(aes_next),
                 .ecb_ready(aes_ready),
                 .ecb_key(aes_key),
                 .ecb_keylen(aes_keylen),
                 .ecb_block(aes_block),
                 .ecb_result(aes_result),

                 .cmac_key(cmac_key),
                 .cmac_keylen(cmac_keylen),
                 .cmac_final_size(cmac_final_size),
                 .cmac_init(cmac_init),
                 .cmac_next(cmac_next),
                 .cmac_finalize(cmac_finalize),
                 .cmac_block(cmac_block),
                 .cmac_result(cmac_result),
                 .cmac_ready(cmac_ready)
                );


  //----------------------------------------------------------------
  // reg_update
  //
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with synchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin: reg_update
      if (!reset_n)
        begin
          ready_reg            <= 1'h1;
          block_reg            <= 128'h0;
          result_reg           <= 128'h0;
          d_reg                <= 128'h0;
          v_reg                <= 128'h0;
          x_reg                <= 128'h0;
          addr_reg             <= 16'h0;
          cs_reg               <= 1'h0;
          we_reg               <= 1'h0;
          block_ctr_reg        <= 16'h0;
          ad_start_reg         <= 16'h0;;
          ad_length_reg        <= 20'h0;
          ad_num_blocks_reg    <= 16'h0;
          ad_final_size_reg    <= 8'h0;
          nonce_start_reg      <= 16'h0;;
          nonce_length_reg     <= 20'h0;
          nonce_num_blocks_reg <= 16'h0;
          nonce_final_size_reg <= 8'h0;
          pc_start_reg         <= 16'h0;;
          pc_length_reg        <= 20'h0;
          pc_num_blocks_reg    <= 16'h0;
          pc_final_size_reg    <= 8'h0;
          core_ctrl_reg        <= CTRL_IDLE;
        end
      else
        begin
          ad_num_blocks_reg    <= ad_num_blocks_new;
          ad_final_size_reg    <= ad_final_size_new;
          nonce_num_blocks_reg <= nonce_num_blocks_new;
          nonce_final_size_reg <= nonce_final_size_new;
          pc_num_blocks_reg    <= pc_num_blocks_new;
          pc_final_size_reg    <= pc_final_size_new;

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

          if (block_we)
            block_reg <= block_new;

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
    begin : s2v_dp
      reg [127 : 0] padded_block;
      reg [127 : 0] xorend0;
      reg [127 : 0] xorend1;

      block_new    = 128'h0;
      block_we     = 1'h0;
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


      if (update_v)
        begin
          v_we  = 1'h1;
        end

      // the xorend() function
      // Masked XOR of second to last block when len(PC) > 16 and
      // len(PC) % 16 != 0. This means that the n LAST bytes in
      // the second to last block should be XOR:ed with the
      // n FIRST bytes of the d_reg.
      case (pc_length[3 : 0])
        4'h0:
          begin
            xorend0 = block_rd;
            xorend1 = block_rd ^ d_reg;
          end

        4'h1:
          begin
            xorend0 = {block_rd[127 : 120], block_rd[119 : 000] ^ d_reg[127 : 008]};
            xorend1 = {block_rd[127 : 120] ^ d_reg[007 : 000], 120'h0};
          end

        4'h2:
          begin
            xorend0 = {block_rd[127 : 112], block_rd[111 : 000] ^ d_reg[127 : 016]};
            xorend1 = {block_rd[127 : 112] ^ d_reg[015 : 000], 112'h0};
          end

        4'h3:
          begin
            xorend0 = {block_rd[127 : 104], block_rd[103 : 000] ^ d_reg[127 : 024]};
            xorend1 = {block_rd[127 : 104] ^ d_reg[023 : 000], 104'h0};
          end

        4'h4:
          begin
            xorend0 = {block_rd[127 : 096], block_rd[095 : 000] ^ d_reg[127 : 032]};
            xorend1 = {block_rd[127 : 096] ^ d_reg[031 : 000], 96'h0};
          end

        4'h5:
          begin
            xorend0 = {block_rd[127 : 088], block_rd[087 : 000] ^ d_reg[127 : 040]};
            xorend1 = {block_rd[127 : 088] ^ d_reg[039 : 000], 88'h0};
          end

        4'h6:
          begin
            xorend0 = {block_rd[127 : 080], block_rd[079 : 000] ^ d_reg[127 : 048]};
            xorend1 = {block_rd[127 : 080] ^ d_reg[047 : 000], 80'h0};
          end

        4'h7:
          begin
            xorend0 = {block_rd[127 : 072], block_rd[071 : 000] ^ d_reg[127 : 056]};
            xorend1 = {block_rd[127 : 072] ^ d_reg[055 : 000], 72'h0};
          end

        4'h8:
          begin
            xorend0 = {block_rd[127 : 064], block_rd[063 : 000] ^ d_reg[127 : 064]};
            xorend1 = {block_rd[127 : 064] ^ d_reg[063 : 000], 64'h0};
          end

        4'h9:
          begin
            xorend0 = {block_rd[127 : 056], block_rd[055 : 000] ^ d_reg[127 : 072]};
            xorend1 = {block_rd[127 : 056] ^ d_reg[071 : 000], 56'h0};
          end

        4'ha:
          begin
            xorend0 = {block_rd[127 : 048], block_rd[047 : 000] ^ d_reg[127 : 080]};
            xorend1 = {block_rd[127 : 048] ^ d_reg[079 : 000], 48'h0};
          end

        4'hb:
          begin
            xorend0 = {block_rd[127 : 040], block_rd[039 : 000] ^ d_reg[127 : 088]};
            xorend1 = {block_rd[127 : 040] ^ d_reg[087 : 000], 40'h0};
          end

        4'hc:
          begin
            xorend0 = {block_rd[127 : 032], block_rd[031 : 000] ^ d_reg[127 : 096]};
            xorend1 = {block_rd[127 : 032] ^ d_reg[095 : 000], 32'h0};
          end

        4'hd:
          begin
            xorend0 = {block_rd[127 : 024], block_rd[023 : 000] ^ d_reg[127 : 104]};
            xorend1 = {block_rd[127 : 024] ^ d_reg[103 : 000], 24'h0};
          end

        4'he:
          begin
            xorend0 = {block_rd[127 : 016], block_rd[015 : 000] ^ d_reg[127 : 112]};
            xorend1 = {block_rd[127 : 016] ^ d_reg[111 : 000], 16'h0};
          end

        4'hf:
          begin
            xorend0 = {block_rd[127 : 008], block_rd[007 : 000] ^ d_reg[127 : 120]};
            xorend1 = {block_rd[127 : 008] ^ d_reg[119 : 000], 8'h0};
          end
      endcase


      // Padding of final block when PC < 16 bytes.
      case (pc_length[3 : 0])
        4'h0: padded_block = {8'h80, {15{8'h0}}};
        4'h1: padded_block = {block_rd[127 : 120], 8'h80, {14{8'h0}}};
        4'h2: padded_block = {block_rd[127 : 112], 8'h80, {13{8'h0}}};
        4'h3: padded_block = {block_rd[127 : 104], 8'h80, {12{8'h0}}};
        4'h4: padded_block = {block_rd[127 : 096], 8'h80, {11{8'h0}}};
        4'h5: padded_block = {block_rd[127 : 088], 8'h80, {10{8'h0}}};
        4'h6: padded_block = {block_rd[127 : 080], 8'h80, {9{8'h0}}};
        4'h7: padded_block = {block_rd[127 : 072], 8'h80, {8{8'h0}}};
        4'h8: padded_block = {block_rd[127 : 064], 8'h80, {7{8'h0}}};
        4'h9: padded_block = {block_rd[127 : 056], 8'h80, {6{8'h0}}};
        4'ha: padded_block = {block_rd[127 : 048], 8'h80, {5{8'h0}}};
        4'hb: padded_block = {block_rd[127 : 040], 8'h80, {4{8'h0}}};
        4'hc: padded_block = {block_rd[127 : 032], 8'h80, {3{8'h0}}};
        4'hd: padded_block = {block_rd[127 : 024], 8'h80, {2{8'h0}}};
        4'he: padded_block = {block_rd[127 : 016], 8'h80, {1{8'h0}}};
        4'hf: padded_block = {block_rd[127 : 008], 8'h80};
      endcase

      if (update_block)
        begin
          block_we = 1'h1;
          case (block_mux)
            BLOCK_DATA:    block_new = block_rd;
            BLOCK_XOR:     block_new = d_reg ^ block_rd;
            BLOCK_XOR_PAD: block_new = d_reg ^ padded_block;
            BLOCK_XOREND0: block_new = xorend0;
            BLOCK_XOREND1: block_new = xorend1;
            default:
              begin
                block_new = 128'h0;
              end
          endcase // case (block_mux)
        end


      case (cmac_inputs)
        CMAC_ZEROES:  cmac_block = 128'h0;
        CMAC_ONE:     cmac_block = 128'h1;
        CMAC_BLOCK:   cmac_block = block_rd;
        CMAC_XOREND0: cmac_block = xorend0;
        CMAC_XOREND1: cmac_block = xorend1;
        CMAC_PAD:     cmac_block = padded_block;
        CMAC_PAD_XOR: cmac_block = padded_block ^d_reg;
        CMAC_FINAL:   cmac_block = d_reg;
      endcase // case (cmac_inputs)


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
      reg [31 : 0] x_tmp;
      reg [127 : 0] mask;

      x_new      = 128'h0;
      x_we       = 1'h0;
      aes_key    = key[255 : 0];
      aes_keylen = mode;
      aes_block  = x_reg;

      // Padding of final block when PC < 16 bytes.
      case (pc_length[3 : 0])
        4'h0: mask = {16{8'hff}};
        4'h1: mask = {{1{8'hff}},  {15{8'h0}}};
        4'h2: mask = {{2{8'hff}},  {14{8'h0}}};
        4'h3: mask = {{3{8'hff}},  {13{8'h0}}};
        4'h4: mask = {{4{8'hff}},  {12{8'h0}}};
        4'h5: mask = {{5{8'hff}},  {11{8'h0}}};
        4'h6: mask = {{6{8'hff}},  {10{8'h0}}};
        4'h7: mask = {{7{8'hff}},  {9{8'h0}}};
        4'h8: mask = {{8{8'hff}},  {8{8'h0}}};
        4'h9: mask = {{9{8'hff}},  {7{8'h0}}};
        4'ha: mask = {{10{8'hff}}, {6{8'h0}}};
        4'hb: mask = {{11{8'hff}}, {5{8'h0}}};
        4'hc: mask = {{12{8'hff}}, {4{8'h0}}};
        4'hd: mask = {{13{8'hff}}, {3{8'h0}}};
        4'he: mask = {{14{8'hff}}, {2{8'h0}}};
        4'hf: mask = {{15{8'hff}}, {1{8'h0}}};
        default:
          begin
            mask = 128'h0;
          end
      endcase

      if (final_wr_block)
        result_new = (block_reg ^ aes_result) & mask;
      else
        result_new = block_reg ^ aes_result;

      // Clear bit 63 and 31 when seeding the counter.
      // See RFC 5297, Section 2.5.
      if (init_ctr)
        begin
          if (encdec)
            x_new = {v_reg[127 : 64], 1'h0, v_reg[62 : 32], 1'h0, v_reg[30 : 0]};
          else
            x_new = {tag_in[127 : 64], 1'h0, tag_in[62 : 32], 1'h0, tag_in[30 : 0]};

          x_we  = 1'h1;
        end

      // 32 bit adder used.
      if (update_ctr)
        begin
          x_tmp = x_reg[31 : 0] + 1'h1;
          x_new = {x_reg[127 : 32], x_tmp};
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
      ad_num_blocks_new    = 16'h0;
      ad_final_size_new    = 8'h0;
      nonce_num_blocks_new = 16'h0;
      nonce_final_size_new = 8'h0;
      pc_num_blocks_new    = 16'h0;
      pc_final_size_new    = 8'h0;


      ad_zlen    = ~|ad_length_reg;
      nonce_zlen = ~|nonce_length_reg;
      pc_zlen    = ~|pc_length_reg;

      if (!ad_zlen)
        begin
          if (ad_length_reg[3 : 0] == 4'h0)
            begin
              ad_num_blocks_new = ad_length_reg[19 : 4];
              ad_final_size_new = 8'h80;
            end
          else
            begin
              ad_num_blocks_new = ad_length_reg[19 : 4] + 1'h1;
              ad_final_size_new = {ad_length_reg[4 : 0], 3'h0};
            end
        end

      if (!nonce_zlen)
        begin
          if (nonce_length_reg[3 : 0] == 4'h0)
            begin
              nonce_num_blocks_new = nonce_length_reg[19 : 4];
              nonce_final_size_new = 8'h80;
            end
          else
            begin
              nonce_num_blocks_new = nonce_length_reg[19 : 4] + 1'h1;
              nonce_final_size_new = {nonce_length_reg[4 : 0], 3'h0};
            end
        end

      if (!pc_zlen)
        begin
          if (pc_length_reg[3 : 0] == 4'h0)
            begin
              pc_num_blocks_new = pc_length_reg[19 : 4];
              pc_final_size_new = 8'h80;
            end
          else
            begin
              pc_num_blocks_new = pc_length_reg[19 : 4] + 1'h1;
              pc_final_size_new = {pc_length_reg[4 : 0], 3'h0};
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
            default:
              begin
              end
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
      aes_next        = 1'h0;
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
      result_we       = 1'h0;
      cmac_inputs     = CMAC_ZEROES;
      update_d        = 1'h0;
      ctrl_d          = D_CMAC;
      update_v        = 1'h0;
      cs_new          = 1'h0;
      cs_we           = 1'h0;
      we_new          = 1'h0;
      we_we           = 1'h0;
      update_block    = 1'h0;
      final_wr_block  = 1'h0;
      block_mux       = BLOCK_XOR;
      cipher_mode     = CMAC_MODE;
      core_ctrl_new   = CTRL_IDLE;
      core_ctrl_we    = 1'h0;

      case (core_ctrl_reg)
        CTRL_IDLE:
          begin
            if (start)
              begin
                if (encdec)
                  begin
                    ready_new     = 1'h0;
                    ready_we      = 1'h1;
                    s2v_init      = 1'h1;
                    cmac_init     = 1'h1;
                    core_ctrl_new = CTRL_S2V_INIT;
                    core_ctrl_we  = 1'h1;
                  end
                else
                  begin
                    cipher_mode   = ECB_MODE;
                    s2v_init      = 1'h1;
                    ready_new     = 1'h0;
                    ready_we      = 1'h1;
                    core_ctrl_new = CTRL_CTR_INIT;
                    core_ctrl_we  = 1'h1;
                  end
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
                    cs_new        = 1'h1;
                    cs_we         = 1'h1;
                    core_ctrl_new = CTRL_S2V_NONCE_INIT;
                    core_ctrl_we  = 1'h1;
                  end

                else
                  begin
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_PC;
                    core_ctrl_new = CTRL_S2V_PC_INIT;
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

                    if (ad_num_blocks_reg == 16'h1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = ad_final_size_reg;
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

                    if (block_ctr_reg == ad_num_blocks_reg - 1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_finalize   = 1'h1;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = ad_final_size_reg;
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

                if (!nonce_zlen)
                  begin
                    cmac_init     = 1'h1;
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_NONCE;
                    cs_new        = 1'h1;
                    cs_we         = 1'h1;
                    core_ctrl_new = CTRL_S2V_NONCE_INIT;
                    core_ctrl_we  = 1'h1;
                  end
                else
                  begin
                    cmac_init     = 1'h1;
                    core_ctrl_new = CTRL_S2V_PC_INIT;
                    core_ctrl_we  = 1'h1;
                  end
              end
          end


        // Wait for cmac to be ready.
        // Check that we got the first block.
        CTRL_S2V_NONCE_INIT:
          begin
            if (cmac_ready)
              begin
                if (ack)
                  begin
                    cs_new = 1'h0;
                    cs_we  = 1'h1;

                    if (nonce_num_blocks_reg == 16'h1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = nonce_final_size_reg;
                        cmac_finalize   = 1'h1;
                        core_ctrl_new   = CTRL_S2V_NONCE_FINAL;
                        core_ctrl_we    = 1'h1;
                      end
                    else
                      begin
                        cmac_next     = 1'h1;
                        cmac_inputs   = CMAC_BLOCK;
                        addr_inc      = 1'h1;
                        cs_new        = 1'h1;
                        cs_we         = 1'h1;
                        core_ctrl_new = CTRL_S2V_NONCE_NEXT;
                        core_ctrl_we  = 1'h1;
                      end
                  end
              end
          end


        // Wait for cmac to be ready.
        // Check that we got the next block.
        CTRL_S2V_NONCE_NEXT:
          begin
            if (cmac_ready)
              begin
                if (ack)
                  begin
                    cs_new = 1'h0;
                    cs_we  = 1'h1;

                    if (block_ctr_reg == nonce_num_blocks_reg - 1)
                      begin
                        update_d        = 1'h1;
                        ctrl_d          = D_DBL;
                        cmac_finalize   = 1'h1;
                        cmac_inputs     = CMAC_BLOCK;
                        cmac_final_size = nonce_final_size_reg;
                        core_ctrl_new   = CTRL_S2V_NONCE_FINAL;
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


        CTRL_S2V_NONCE_FINAL:
          begin
            if (cmac_ready)
              begin
                update_d      = 1'h1;
                ctrl_d        = D_XOR;
                cmac_init     = 1'h1;
                core_ctrl_new = CTRL_S2V_PC_INIT;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_S2V_PC_INIT:
          begin
            if (cmac_ready)
              begin
                if (pc_zlen)
                  begin
                    // Handle zero length PC.
                    update_d      = 1'h1;
                    ctrl_d        = D_DBL;
                    core_ctrl_new = CTRL_S2V_PC_FINAL1;
                    core_ctrl_we  = 1'h1;
                  end

                else if (pc_length_reg < 20'h10)
                  begin
                    // Handle single block PC < 16 bytes.
                    cs_new        = 1'h1;
                    cs_we         = 1'h1;
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_PC;
                    update_d      = 1'h1;
                    ctrl_d        = D_DBL;
                    core_ctrl_new = CTRL_S2V_PC_FINAL0;
                    core_ctrl_we  = 1'h1;
                  end

                else
                  begin
                    // Handle PC >= 16 bytes.
                    cs_new        = 1'h1;
                    cs_we         = 1'h1;
                    addr_set      = 1'h1;
                    addr_mux      = ADDR_PC;
                    core_ctrl_new = CTRL_S2V_PC_NEXT0;
                    core_ctrl_we  = 1'h1;
                  end
              end
          end


        // Wait for cmac to be ready.
        // Check that we got the next block.
        CTRL_S2V_PC_NEXT0:
          begin
            if (ack)
              begin
                cs_new = 1'h0;
                cs_we  = 1'h1;

                if (block_ctr_reg == pc_num_blocks_reg - 1)
                  begin
                    cmac_finalize   = 1'h1;
                    cmac_inputs     = CMAC_XOREND1;
                    cmac_final_size = pc_final_size_reg;
                    core_ctrl_new   = CTRL_S2V_PC_FINAL2;
                    core_ctrl_we    = 1'h1;
                  end

                else if (block_ctr_reg == pc_num_blocks_reg - 2)
                  begin
                    cmac_next       = 1'h1;
                    cmac_inputs     = CMAC_XOREND0;
                    core_ctrl_new   = CTRL_S2V_PC_NEXT1;
                    core_ctrl_we    = 1'h1;
                  end

                else
                  begin
                    cmac_next       = 1'h1;
                    cmac_inputs     = CMAC_BLOCK;
                    core_ctrl_new   = CTRL_S2V_PC_NEXT1;
                    core_ctrl_we    = 1'h1;
                  end
              end
          end


        CTRL_S2V_PC_NEXT1:
          begin
            if (cmac_ready)
              begin
                addr_inc      = 1'h1;
                cs_new        = 1'h1;
                cs_we         = 1'h1;
                core_ctrl_new = CTRL_S2V_PC_NEXT0;
                core_ctrl_we  = 1'h1;
              end
          end

        CTRL_S2V_PC_FINAL0:
          begin
            if (ack)
              begin
                core_ctrl_new = CTRL_S2V_PC_FINAL1;
                core_ctrl_we  = 1'h1;
              end
          end

        CTRL_S2V_PC_FINAL1:
          begin
            cs_new        = 1'h0;
            cs_we         = 1'h1;
            cmac_finalize = 1'h1;
            cmac_inputs   = CMAC_PAD_XOR;

            if (pc_length >= 20'h10)
              cmac_final_size = pc_final_size_reg;
            else
              cmac_final_size = AES_BLOCK_SIZE;

            core_ctrl_new   = CTRL_S2V_PC_FINAL2;
            core_ctrl_we    = 1'h1;
          end


        CTRL_S2V_PC_FINAL2:
          begin
            if (cmac_ready)
              begin
                update_v = 1'h1;

                if (!pc_zlen)
                  begin
                    if (encdec)
                      begin
                        cipher_mode   = ECB_MODE;
                        core_ctrl_new = CTRL_CTR_INIT;
                        core_ctrl_we  = 1'h1;
                      end
                    else
                      begin
                        core_ctrl_new = CTRL_DONE;
                        core_ctrl_we  = 1'h1;
                      end
                  end
                else
                  begin
                    core_ctrl_new = CTRL_DONE;
                    core_ctrl_we  = 1'h1;
                  end
              end
          end


        // Handle the edge case when all inputs to
        // S2V have zero length, i.e. don't exist.
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


        CTRL_CTR_INIT:
          begin
            if (pc_zlen)
              begin
                s2v_init      = 1'h1;
                cmac_init     = 1'h1;
                core_ctrl_new = CTRL_S2V_INIT;
                core_ctrl_we  = 1'h1;
              end
            else
              begin
                cipher_mode   = ECB_MODE;
                addr_set      = 1'h1;
                addr_mux      = ADDR_PC;
                init_ctr      = 1'h1;
                core_ctrl_new = CTRL_CTR_NEXT;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_NEXT:
          begin
            cipher_mode = ECB_MODE;
            if (aes_ready)
              begin
                aes_next      = 1'h1;
                core_ctrl_new = CTRL_CTR_READ;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_READ:
          begin
            cipher_mode = ECB_MODE;
            if (aes_ready)
              begin
                cs_new        = 1'h1;
                cs_we         = 1'h1;
                core_ctrl_new = CTRL_CTR_RACK;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_RACK:
          begin
            cipher_mode = ECB_MODE;
            if (ack)
              begin
                cs_new        = 1'h0;
                cs_we         = 1'h1;
                update_block  = 1'h1;
                block_mux     = BLOCK_DATA;
                core_ctrl_new = CTRL_CTR_XOR;
                core_ctrl_we  = 1'h1;
              end
          end


        CTRL_CTR_XOR:
          begin
            cipher_mode = ECB_MODE;
            if (block_ctr_reg == pc_num_blocks_reg - 1)
              final_wr_block = 1'h1;

            result_we      = 1'h1;
            update_ctr     = 1'h1;
            core_ctrl_new  = CTRL_CTR_WRITE;
            core_ctrl_we   = 1'h1;
          end


        CTRL_CTR_WRITE:
          begin
            cipher_mode   = ECB_MODE;
            cs_new        = 1'h1;
            cs_we         = 1'h1;
            we_new        = 1'h1;
            we_we         = 1'h1;
            core_ctrl_new = CTRL_CTR_WACK;
            core_ctrl_we  = 1'h1;
          end

        CTRL_CTR_WACK:
          begin
            if (ack)
              begin
                cs_new        = 1'h0;
                cs_we         = 1'h1;
                we_new        = 1'h0;
                we_we         = 1'h1;

                if (block_ctr_reg == pc_num_blocks_reg - 1)
                  begin
                    if (encdec)
                      begin
                        core_ctrl_new = CTRL_DONE;
                        core_ctrl_we  = 1'h1;
                      end
                    else
                      begin
                        s2v_init      = 1'h1;
                        cmac_init     = 1'h1;
                        core_ctrl_new = CTRL_S2V_INIT;
                        core_ctrl_we  = 1'h1;
                      end
                  end
                else
                  begin
                    cipher_mode   = ECB_MODE;
                    addr_inc      = 1'h1;
                    core_ctrl_new = CTRL_CTR_NEXT;
                    core_ctrl_we  = 1'h1;
                  end
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
