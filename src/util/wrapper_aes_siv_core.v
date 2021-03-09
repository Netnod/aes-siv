//======================================================================
//
// wrapper_aes_siv_core.v
// ----------------------
// Wrapper for the aes_siv_core to allow test implementations in
// FPGA devices with I/O constraints. The wrapper does not really
// provide any useful functionality and is not intended to be used
// in any real design.
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

module wrapper_aes_siv_core(
                            input wire            clk,
                            input wire            reset_n,

                            input wire [127 : 0]  block_in,
                            output wire [127 : 0] block_out,
                            input wire   [2 : 0]  mux_ctrl
                            );


  //----------------------------------------------------------------
  // Registers.
  //----------------------------------------------------------------
  reg [127 : 0] block_in_reg;
  reg [127 : 0] block_out_reg;
  reg [127 : 0] block_out_new;
  reg [2 :  0]  mux_ctrl_reg;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  reg            core_encdec;
  reg [511 : 0]  core_key;
  reg            core_mode;
  reg            core_start;
  reg [15 :0]    core_ad_start;
  reg [19 :0]    core_ad_length;
  reg [15 :0]    core_nonce_start;
  reg [19 :0]    core_nonce_length;
  reg [15 :0]    core_pc_start;
  reg [19 :0]    core_pc_length;
  wire           core_cs;
  wire           core_we;
  reg            core_ack;
  wire [15 : 0]  core_addr;
  reg [127 : 0]  core_block_rd;
  wire [127 : 0] core_block_wr;
  reg [127 : 0]  core_tag_in;
  wire [127 : 0] core_tag_out;
  wire           core_tag_ok;
  wire           core_ready;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign block_out = block_out_reg;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_siv_core core(
                    .clk(clk),
                    .reset_n(reset_n),
                    .encdec(core_encdec),
                    .key(core_key),
                    .mode(core_mode),
                    .start(core_start),
                    .ad_start(core_ad_start),
                    .ad_length(core_ad_length),
                    .nonce_start(core_nonce_start),
                    .nonce_length(core_nonce_length),
                    .pc_start(core_pc_start),
                    .pc_length(core_pc_length),
                    .cs(core_cs),
                    .we(core_we),
                    .ack(core_ack),
                    .addr(core_addr),
                    .block_rd(core_block_rd),
                    .block_wr(core_block_wr),
                    .tag_in(core_tag_in),
                    .tag_out(core_tag_out),
                    .tag_ok(core_tag_ok),
                    .ready(core_ready)
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
          mux_ctrl_reg  <= 3'h0;
          block_in_reg  <= 128'h0;
          block_out_reg <= 128'h0;
        end
      else
        begin
          mux_ctrl_reg  <= mux_ctrl;
          block_in_reg  <= block_in;
          block_out_reg <= block_out_new;
        end
    end // reg_update


  //----------------------------------------------------------------
  // pinmux
  //
  // Somewhat arbitrarily decided mux of core inputs and outputs.
  //----------------------------------------------------------------
  always @*
    begin : pinmux
      core_encdec       = 1'h0;
      core_key          = 512'h0;
      core_mode         = 1'h0;
      core_start        = 1'h0;
      core_ad_start     = 16'h0;
      core_ad_length    = 20'h0;
      core_nonce_start  = 16'h0;
      core_nonce_length = 20'h0;
      core_pc_start     = 16'h0;
      core_pc_length    = 20'h0;
      core_ack          = 1'h0;
      core_block_rd     = 128'h0;
      core_tag_in       = 128'h0;
      block_out_new     = 128'h0;

      case (mux_ctrl_reg)
        0:
          begin
            core_ad_start     = block_in_reg[15 : 0];
            core_ad_length    = block_in_reg[35 : 16];
            core_encdec       = block_in_reg[40];
            core_mode         = block_in_reg[41];
            core_start        = block_in_reg[42];
            core_ack          = block_in_reg[43];
            core_nonce_start  = block_in_reg[63 : 48];
            core_nonce_length = block_in_reg[83 : 64];
            core_pc_start     = block_in_reg[105 : 90];
            core_pc_length    = block_in_reg[125 : 106];
            block_out_new     = {108'h0, core_cs, core_we, core_addr,
                                 core_tag_ok, core_ready};
          end


        1:
          begin
            core_block_rd = block_in_reg;
            block_out_new = core_block_wr;
          end


        2:
          begin
            core_tag_in   = block_in_reg;
            block_out_new = core_tag_out;
          end

        3:
          begin
            core_key[127 : 0] = block_in_reg;
          end

        4:
          begin
            core_key[255 : 128] = block_in_reg;
          end

        5:
          begin
            core_key[383 : 256] = block_in_reg;
          end

        6:
          begin
            core_key[511 : 384] = block_in_reg;
          end

        default:
          begin
          end
      endcase // case (mux_ctrl)
    end

endmodule // wrapper_aes_siv_core

//======================================================================
// EOF wrapper_aes_siv_core.v
//======================================================================
