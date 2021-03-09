//======================================================================
//
// aes_siv.v
// ---------
// Top level wrapper for the aes_siv_core. The top level wrapper
// includes a local memory used by the aes-siv core for processing.
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

module aes_siv(
               // Clock and reset.
               input wire           clk,
               input wire           reset_n,

               // Control.
               input wire           cs,
               input wire           we,

               // Data ports.
               input wire  [7 : 0]  address,
               input wire  [31 : 0] write_data,
               output wire [31 : 0] read_data
              );

  //----------------------------------------------------------------
  // Internal constant and parameter definitions.
  //----------------------------------------------------------------
  localparam ADDR_NAME0        = 8'h00;
  localparam ADDR_NAME1        = 8'h01;
  localparam ADDR_VERSION      = 8'h02;

  localparam ADDR_CTRL         = 8'h08;
  localparam CTRL_START_BIT    = 0;

  localparam ADDR_STATUS       = 8'h09;
  localparam STATUS_READY_BIT  = 0;
  localparam STATUS_TAG_OK_BIT = 1;

  localparam ADDR_CONFIG       = 8'h0a;
  localparam CTRL_ENCDEC_BIT   = 0;
  localparam CTRL_MODE_BIT     = 1;

  localparam ADDR_AD_START     = 8'h10;
  localparam ADDR_AD_LENGTH    = 8'h11;

  localparam ADDR_NONCE_START  = 8'h20;
  localparam ADDR_NONCE_LENGTH = 8'h21;

  localparam ADDR_PC_START     = 8'h30;
  localparam ADDR_PC_LENGTH    = 8'h31;

  localparam ADDR_KEY0         = 8'h40;
  localparam ADDR_KEY15        = 8'h4f;

  localparam ADDR_TAG_IN0      = 8'h50;
  localparam ADDR_TAG_IN3      = 8'h53;

  localparam ADDR_TAG_OUT0     = 8'h60;
  localparam ADDR_TAG_OUT3     = 8'h63;

  localparam ADDR_MEM_START    = 8'h80;
  localparam ADDR_MEM_END      = 8'hff;

  localparam CORE_NAME0        = 32'h6165732d; // "aes-"
  localparam CORE_NAME1        = 32'h73697620; // "siv "
  localparam CORE_VERSION      = 32'h302e3130; // "0.10"


  //----------------------------------------------------------------
  // Registers including update variables and write enable.
  //----------------------------------------------------------------
  reg          start_reg;
  reg          start_new;

  reg          encdec_reg;
  reg          mode_reg;
  reg          config_we;

  reg [31 : 0] key_reg [0 : 15];
  reg          key_we;

  reg [15 :0]  ad_start_reg;
  reg          ad_start_we;

  reg [19 :0]  ad_length_reg;
  reg          ad_length_we;

  reg [15 :0]  nonce_start_reg;
  reg          nonce_start_we;

  reg [19 :0]  nonce_length_reg;
  reg          nonce_length_we;

  reg [15 :0]  pc_start_reg;
  reg          pc_start_we;

  reg [19 :0]  pc_length_reg;
  reg          pc_length_we;

  reg [31 : 0] tag_in_reg [0 : 3];
  reg          tag_in_we;


  //----------------------------------------------------------------
  // Wires.
  //----------------------------------------------------------------
  wire [511 : 0] core_key;
  wire           core_cs;
  wire           core_we;
  reg            core_ack;
  wire [15 : 0]  core_addr;
  reg [127 : 0]  core_block_rd;
  wire [127 : 0] core_block_wr;
  wire [127 : 0] core_tag_in;
  wire [127 : 0] core_tag_out;
  wire           core_tag_ok;
  wire           core_ready;

  reg            mem_cs;
  reg            mem_we;
  wire           mem_ack;
  reg  [15 : 0]  mem_addr;
  reg [127 : 0]  mem_block_wr;
  wire [127 : 0] mem_block_rd;

  reg            api_cs;
  reg            api_we;

  reg [31 : 0]   tmp_read_data;


  //----------------------------------------------------------------
  // Concurrent connectivity for ports etc.
  //----------------------------------------------------------------
  assign core_key = {key_reg[00], key_reg[01], key_reg[02], key_reg[03],
                     key_reg[04], key_reg[05], key_reg[06], key_reg[07],
                     key_reg[08], key_reg[09], key_reg[10], key_reg[11],
                     key_reg[12], key_reg[13], key_reg[14], key_reg[15]};


  assign core_tag_in = {tag_in_reg[0], tag_in_reg[1],
                        tag_in_reg[2], tag_in_reg[3]};

  assign read_data = tmp_read_data;


  //----------------------------------------------------------------
  // core instantiation.
  //----------------------------------------------------------------
  aes_siv_core core(
                    .clk(clk),
                    .reset_n(reset_n),
                    .encdec(encdec_reg),
                    .key(core_key),
                    .mode(mode_reg),
                    .start(start_reg),
                    .ad_start(ad_start_reg),
                    .ad_length(ad_length_reg),
                    .nonce_start(nonce_start_reg),
                    .nonce_length(nonce_length_reg),
                    .pc_start(pc_start_reg),
                    .pc_length(pc_length_reg),
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


  tb_core_mem mem(
                  .clk(clk),
                  .reset_n(reset_n),
                  .cs(mem_cs),
                  .we(mem_we),
                  .ack(mem_ack),
                  .addr(mem_addr),
                  .block_wr(mem_block_wr),
                  .block_rd(mem_block_rd)
                 );


  //----------------------------------------------------------------
  // reg_update
  // Update functionality for all registers in the core.
  // All registers are positive edge triggered with asynchronous
  // active low reset.
  //----------------------------------------------------------------
  always @ (posedge clk or negedge reset_n)
    begin : reg_update
      integer i;

      if (!reset_n)
        begin
          for (i = 0 ; i < 16 ; i = i + 1)
            key_reg[i] <= 32'h0;

          for (i = 0 ; i < 4 ; i = i + 1)
            tag_in_reg[i] <= 32'h0;

          ad_start_reg     <= 16'h0;
          ad_length_reg    <= 20'h0;
          nonce_start_reg  <= 16'h0;
          nonce_length_reg <= 20'h0;
          pc_start_reg     <= 16'h0;
          pc_length_reg    <= 20'h0;
          start_reg        <= 1'h0;
          encdec_reg       <= 1'h0;
          mode_reg         <= 1'h0;
        end
      else
        begin
          start_reg  <= start_new;

          if (config_we)
            begin
              encdec_reg <= write_data[CTRL_ENCDEC_BIT];
              mode_reg   <= write_data[CTRL_MODE_BIT];
            end

          if (ad_start_we)
            ad_start_reg <= write_data[15 : 0];

          if (ad_length_we)
            ad_length_reg <= write_data[20 : 0];

          if (nonce_start_we)
            nonce_start_reg <= write_data[15 : 0];

          if (nonce_length_we)
            nonce_length_reg <= write_data[20 : 0];

          if (pc_start_we)
            pc_start_reg <= write_data[15 : 0];

          if (pc_length_we)
            pc_length_reg <= write_data[20 : 0];

          if (tag_in_we)
            tag_in_reg[address[1 : 0]] <= write_data;

          if (key_we)
            key_reg[address[3 : 0]] <= write_data;
        end
    end // reg_update


  //----------------------------------------------------------------
  // mem_mux
  //
  // Allow API and core to share the memory.
  // Note that the access from the API is really incorrect.
  //----------------------------------------------------------------
  always @*
    begin : mem_mux
      core_ack      = 1'h0;
      core_block_rd = 128'h0;

      if (core_ready)
        begin
          mem_cs   = api_cs;
          mem_we   = api_we;
          mem_addr = {9'h0, address[6 : 0]};
          mem_block_wr = {4{write_data}};
        end
      else
        begin
          core_ack     = mem_ack;
          mem_cs       = core_cs;
          mem_we       = core_we;
          mem_addr     = core_addr;
          mem_block_wr = core_block_wr;
        end
    end


  //----------------------------------------------------------------
  // api
  //
  // The interface command decoding logic.
  //----------------------------------------------------------------
  always @*
    begin : api
      start_new       = 1'h0;
      config_we       = 1'h0;
      ad_start_we     = 1'h0;
      ad_length_we    = 1'h0;
      nonce_start_we  = 1'h0;
      nonce_length_we = 1'h0;
      pc_start_we     = 1'h0;
      pc_length_we    = 1'h0;
      key_we          = 1'h0;
      tag_in_we       = 1'h0;
      api_cs          = 1'h0;
      api_we          = 1'h0;
      tmp_read_data   = 32'h0;


      if (cs)
        begin
          if (we)
            begin
              if (address == ADDR_CTRL)
                begin
                  start_new = write_data[CTRL_START_BIT];
                end

              if (address == ADDR_CONFIG)
                config_we = 1'h1;

              if (ADDR_AD_START)
                ad_start_we = 1'h1;

              if (ADDR_AD_LENGTH)
                ad_length_we = 1'h1;

              if (ADDR_NONCE_START)
                nonce_start_we = 1'h1;

              if (ADDR_NONCE_LENGTH)
                nonce_length_we = 1'h1;

              if (ADDR_PC_START)
                pc_start_we = 1'h1;

              if (ADDR_PC_LENGTH)
                pc_length_we = 1'h1;

              if ((address >= ADDR_KEY0) && (address <= ADDR_KEY15))
                key_we = 1'h1;

              if ((address >= ADDR_TAG_IN0) && (address <= ADDR_TAG_IN3))
                tag_in_we = 1'h1;

              if ((address >= ADDR_MEM_START) && (address <= ADDR_MEM_END))
                begin
                  api_cs = 1'h1;
                  api_we = 1'h1;
                end
            end // if (we)

          else
            begin
              case (address)
                ADDR_NAME0:   tmp_read_data = CORE_NAME0;
                ADDR_NAME1:   tmp_read_data = CORE_NAME1;
                ADDR_VERSION: tmp_read_data = CORE_VERSION;
                ADDR_STATUS:  tmp_read_data = {30'h0, core_tag_ok, core_ready};

                default:
                  begin
                  end
              endcase // case (address)


              if ((address >= ADDR_TAG_OUT0) && (address <= ADDR_TAG_OUT3))
                tmp_read_data = core_tag_out[(3 - (address - ADDR_TAG_OUT0)) * 32 +: 32];


              if ((address >= ADDR_MEM_START) && (address <= ADDR_MEM_END))
                begin
                  api_cs        = 1'h1;
                  tmp_read_data = mem_block_rd[31 : 0];
                end
            end
        end
    end // addr_decoder
endmodule // aes_siv

//======================================================================
// EOF aes_siv.v
//======================================================================
