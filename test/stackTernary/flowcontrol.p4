 /* -*- P4_16 -*- */

/*
 * Copyright (c) pcl, Inc.
 *
 *
 *Author：pcl:lll,dgl
 */
 // test for header stack




#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
#include "common/headers.p4"
#include "common/util.p4"
/* MACROS */

#define CPU_PORT 320
#define THRESHOLD_NUMBER 100
#define FLAG_NUM 6
#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_num_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header dns_t {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

// label length
header dns_q_label_len_t {
    bit<8> label_len;
}

header domain_byte_t {
    bit<8> domain_byte;
}

header domain_byte_32_t {
    bit<256> byte_32;
}
header bit_test_t{
    bit<512> bit_test;
}
struct my_ingress_metadata_t {
    bit<4> tcp_dataOffset;
    bit<16> tcp_window;
    bit<16> udp_length;
    bit<16> srcport;
    bit<16> dstport;
    bit<112> bin_feature; // total binary feature
    bit<4> domain_index;
    bit<32> domain_stack_index;
    bit<256> domain_part;
}

struct my_ingress_headers_t {
    // my change
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t       udp; 
    // DNS
    dns_t       dns_header;
    dns_q_label_len_t q_label_len;
    domain_byte_t[32] total_domain;
    domain_byte_32_t q1_part1;
    domain_byte_t[32] q1_part2_stack;

    domain_byte_t[32] total_domain_2;
    domain_byte_32_t q2_part1;
    domain_byte_t[32] q2_part2_stack;

    domain_byte_t[32] total_domain_3;
    domain_byte_32_t q3_part1;
    domain_byte_t[32] q3_part2_stack;

    domain_byte_t[32] total_domain_4;
    domain_byte_32_t q4_part1;
    domain_byte_t[32] q4_part2_stack;

    domain_byte_t[32] total_domain_5;
    domain_byte_32_t q5_part1;
    domain_byte_t[32] q5_part2_stack;

    domain_byte_t[32] total_domain_6;
    domain_byte_32_t q6_part1;
    domain_byte_t[32] q6_part2_stack;

    domain_byte_t[32] total_domain_7;
    domain_byte_32_t q7_part1;
    domain_byte_t[32] q7_part2_stack;
    bit_test_t bit_test;
}

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_8021q = 0x8100;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser IngressParser(packet_in        pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    ParserCounter() counter;
    //TofinoIngressParser() tofino_parser;
    state start {
        pkt.extract(ig_intr_md);
        transition parse_port_metadata;
    }
    
   state parse_port_metadata {
       pkt.advance(PORT_METADATA_SIZE);
       transition parse_ethernet;
   }
    //
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4   : parse_ipv4;
            // default: accept;
        }
    }
    
   
    state parse_ipv4 {
        
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP   : parse_tcp;
            PROTO_UDP   : parse_udp;
            // default: accept;
        }
   }
     
    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.tcp_dataOffset = hdr.tcp.dataOffset;
        meta.tcp_window = hdr.tcp.window;
        meta.udp_length = 0x0;
        meta.srcport=hdr.tcp.srcPort;
        meta.dstport=hdr.tcp.dstPort;
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.tcp_dataOffset = 0x0;
        meta.tcp_window = 0x0;
        meta.udp_length = hdr.udp.length_;
        meta.srcport=hdr.udp.srcPort;
        meta.dstport=hdr.udp.dstPort;
        // transition accept; 
        transition select (hdr.udp.srcPort) {
            53: parse_dns;
            default: accept;
        }
    }

    // parse dns query
    state parse_dns {
        pkt.extract(hdr.dns_header);
        transition select(hdr.dns_header.is_response) {
            // 0 is query
            0: parse_dns_query;
            default: accept;
        }
    }
    
    state parse_dns_query {
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32
            0x00 &&& 0xE0: parse_q1_part1;
            0x20: parse_q1_part1;
            // > 32
            default: parse_q1_more_than_32;
        }
    }

    state parse_q1_part1 {
        pkt.extract(hdr.total_domain.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q2;
            false: parse_q1_part1;
        }
    }

    state parse_q1_more_than_32 {
        pkt.extract(hdr.q1_part1);
        counter.decrement(8w32);
        transition parse_q1_part2;
    }

    state parse_q1_part2 {
        pkt.extract(hdr.q1_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q2;
            false: parse_q1_part2;
        }
    }

    state finish_parse_domain {
        transition accept;
    }
    // label 2
    state parse_q2 {
        meta.domain_stack_index = hdr.total_domain.lastIndex;
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32 format: value &&& mask
            0x00 &&& 0xE0: parse_q2_part1;
            0x20: parse_q2_part1;
            // > 32
            default: parse_q2_more_than_32;
        }
    }
    
    state parse_q2_part1 {
        pkt.extract(hdr.total_domain_2.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q3;
            false: parse_q2_part1;
        }
    }

    state parse_q2_more_than_32 {
        pkt.extract(hdr.q2_part1);
        counter.decrement(8w32);
        transition parse_q2_part2;
    }

    state parse_q2_part2 {
        pkt.extract(hdr.q2_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q3;
            false: parse_q2_part2;
        }
    }

    // label 3
    state parse_q3 {
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32
            0x00 &&& 0xE0: parse_q3_part1;
            0x20: parse_q3_part1;
            // > 32
            default: parse_q3_more_than_32;
        }
    }
    
    state parse_q3_part1 {
        pkt.extract(hdr.total_domain_3.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q4;
            false: parse_q3_part1;
        }
    }

    state parse_q3_more_than_32 {
        pkt.extract(hdr.q3_part1);
        counter.decrement(8w32);
        transition parse_q3_part2;
    }

    state parse_q3_part2 {
        pkt.extract(hdr.q3_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q4;
            false: parse_q3_part2;
        }
    }

    // label 4
    state parse_q4 {
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32
            0x00 &&& 0xE0: parse_q4_part1;
            0x20: parse_q4_part1;
            // > 32
            default: parse_q4_more_than_32;
        }
    }
    
    state parse_q4_part1 {
        pkt.extract(hdr.total_domain_4.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q5;
            false: parse_q4_part1;
        }
    }

    state parse_q4_more_than_32 {
        pkt.extract(hdr.q4_part1);
        counter.decrement(8w32);
        transition parse_q4_part2;
    }

    state parse_q4_part2 {
        pkt.extract(hdr.q4_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q5;
            false: parse_q4_part2;
        }
    }

    // label 5
    // state parse_q5 {
    //     pkt.extract(hdr.q_label_len);
    //     counter.set(hdr.q_label_len.label_len);
    //     transition select(hdr.q_label_len.label_len) {
    //         // 0
    //         0x00: finish_parse_domain;
    //         // <= 32
    //         0x00 &&& 0xE0: parse_q5_part1;
    //         0x20: parse_q5_part1;
    //         // > 32
    //         default: parse_q5_more_than_32;
    //     }
    // }
    state parse_q5 {
        transition accept;
    }
    
    state parse_q5_part1 {
        pkt.extract(hdr.total_domain_5.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q6;
            false: parse_q5_part1;
        }
    }

    state parse_q5_more_than_32 {
        pkt.extract(hdr.q5_part1);
        counter.decrement(8w32);
        transition parse_q5_part2;
    }

    state parse_q5_part2 {
        pkt.extract(hdr.q5_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q6;
            false: parse_q5_part2;
        }
    }

    // label 6
    state parse_q6 {
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32
            0x00 &&& 0xE0: parse_q6_part1;
            0x20: parse_q6_part1;
            // > 32
            default: parse_q6_more_than_32;
        }
    }
    
    state parse_q6_part1 {
        pkt.extract(hdr.total_domain_6.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q7;
            false: parse_q6_part1;
        }
    }

    state parse_q6_more_than_32 {
        pkt.extract(hdr.q6_part1);
        counter.decrement(8w32);
        transition parse_q6_part2;
    }

    state parse_q6_part2 {
        pkt.extract(hdr.q6_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q7;
            false: parse_q6_part2;
        }
    }

    // label 7
    state parse_q7 {
        pkt.extract(hdr.q_label_len);
        counter.set(hdr.q_label_len.label_len);
        transition select(hdr.q_label_len.label_len) {
            // 0
            0x00: finish_parse_domain;
            // <= 32
            0x00 &&& 0xE0: parse_q7_part1;
            0x20: parse_q7_part1;
            // > 32
            default: parse_q7_more_than_32;
        }
    }
    
    state parse_q7_part1 {
        pkt.extract(hdr.total_domain_7.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q8;
            false: parse_q7_part1;
        }
    }

    state parse_q7_more_than_32 {
        pkt.extract(hdr.q7_part1);
        counter.decrement(8w32);
        transition parse_q7_part2;
    }

    state parse_q7_part2 {
        pkt.extract(hdr.q7_part2_stack.next);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_q8;
            false: parse_q7_part2;
        }
    }

    state parse_q8 {
        transition accept;
    }
}

   
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md
     )
{   
    
    
    action ac_test_stack() {
        // meta.domain_stack_index = hdr.total_domain.lastIndex;
        meta.domain_part[7:0] = hdr.total_domain[0].domain_byte;
    }

    @pragma stage 0
    table tb_test_stack{
        actions = {
            ac_test_stack;
        }
        default_action = ac_test_stack;
    }

    apply {
        tb_test_stack.apply();


        ig_tm_md.bypass_egress = 1w1;
    }
  
}


control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
   // Resubmit() resubmit;
    apply {
        // resubmit with resubmit_data
      // if (ig_dprsr_md.resubmit_type == 2) {
      //     resubmit.emit(meta.resubmit_data);
      // }
       pkt.emit(hdr);
    }
}



/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;


