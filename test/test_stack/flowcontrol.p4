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
header bit_test_t{
    bit<512> bit_test;
}
header total_payload_t{
    bit<2048> total_payload;
}
struct my_ingress_metadata_t {
    bit<4> tcp_dataOffset;
    bit<16> tcp_window;
    bit<16> udp_length;
    bit<16> srcport;
    bit<16> dstport;
    bit<112> bin_feature; // total binary feature
    bit<4> domain_index;
    bit<8> total_domain_len;
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
    domain_byte_t[32] total_domain_1;
    domain_byte_t[32] total_domain_2;
    domain_byte_t[32] total_domain_3;
    domain_byte_t[32] total_domain_4;
    domain_byte_t[32] total_domain_5;
    domain_byte_t[32] total_domain_6;
    domain_byte_t[32] total_domain_7;
    bit_test_t bit_test;
    total_payload_t total_payload;
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
    ParserCounter() label_counter;
    ParserCounter() domain_counter_32;
    bit<8> tmp_domain_len;
    //TofinoIngressParser() tofino_parser;
    state start {
        pkt.extract(ig_intr_md);
        tmp_domain_len = 0;
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
        meta.domain_index = 0;
        meta.total_domain_len = 0;
        transition select(hdr.dns_header.is_response) {
            // 0 is query
            0: parse_dns_query_0;
            default: accept;
        }
    }
    // test for total paylaod
    // state parse_dns {
    //     pkt.extract(hdr.dns_header);
    //     pkt.extract(hdr.total_payload);
    //     transition accept;
    // }

    
    // state parse_dns_query {
    //     pkt.extract(hdr.q_label_len);
    //     counter.set(hdr.q_label_len.label_len);
    //     domain_counter_32.set(8w32);
    //     transition select(counter.is_zero()) {
    //         true: finish_parse_domain;
    //         false: parse_domain_byte;
    //     }
    // }
    // state parse_domain_byte {
    //     pkt.extract(hdr.total_domain.next);
    //     counter.decrement(8w1);
    //     transition select(counter.is_zero()) {
    //         true: parse_dns_query;
    //         false: parse_domain_byte;
    //     }
    // }
    state parse_dns_query_0 {
        pkt.extract(hdr.q_label_len);
        label_counter.set(hdr.q_label_len.label_len);
        domain_counter_32.set(8w8);
        transition estimate_32_0;
    }

    state estimate_32_0 {
        transition select(domain_counter_32.is_zero()) {
            true: set_domain_counter_1;
            false: estimate_label_0;
        }
    }

    state estimate_label_0 {
        transition select(label_counter.is_zero()) {
            true: reset_label_0;
            false: parse_domain_byte_0;
        }
    }

    state reset_label_0 {
        pkt.extract(hdr.q_label_len);
        label_counter.set(hdr.q_label_len.label_len);
        transition select(label_counter.is_zero()) {
            true: finish_parse_domain;
            false: parse_domain_byte_0;
        }
    }

    state parse_domain_byte_0 {
        pkt.extract(hdr.total_domain.next);
        label_counter.decrement(8w1);
        domain_counter_32.decrement(8w1);
        transition estimate_32_0;
    }

    state finish_parse_domain {
        transition accept;
    }

    // go to domain_1
    state set_domain_counter_1 {
        domain_counter_32.set(8w8);

        transition estimate_32_1;
    }
    
    state estimate_32_1 {
        transition select(domain_counter_32.is_zero()) {
            true: set_domain_counter_2;
            false: estimate_label_1;
        }
    }

    state estimate_label_1 {
        transition select(label_counter.is_zero()) {
            true: reset_label_1;
            false: parse_domain_byte_1;
        }
    }

    state reset_label_1 {
        pkt.extract(hdr.q_label_len);
        label_counter.set(hdr.q_label_len.label_len);
        transition select(label_counter.is_zero()) {
            true: finish_parse_domain;
            false: parse_domain_byte_1;
        }
    }

    state parse_domain_byte_1 {

        pkt.extract(hdr.total_domain_1.next);
        label_counter.decrement(8w1);
        domain_counter_32.decrement(8w1);
        // transition accept;
        transition estimate_32_1;
    }

    // go to domain_2
    state set_domain_counter_2 {
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
    
    
    action ac_parse_ip_feature() {
        meta.bin_feature[71:68] = hdr.ipv4.ihl;
        meta.bin_feature[67:60] = hdr.ipv4.diffserv;
        // meta.bin_feature[75:68] = (bit<8>)hdr.ipv4.flags;
        meta.bin_feature[59:52] = hdr.ipv4.ttl;
        meta.bin_feature[15:0] = hdr.ipv4.totalLen;
        meta.bin_feature[79:72] = hdr.ipv4.protocol;
        // modify header for test
        // hdr.ipv4.hdrChecksum = 0x1;
    }
    action ac_parse_tcp_feature() {
        // meta.bin_feature[67:52] = hdr.tcp.srcPort;
        // meta.bin_feature[83:68] = hdr.tcp.dstPort;
        // meta.bin_feature[51:48] = hdr.tcp.dataOffset;
        meta.bin_feature[51:48] = meta.tcp_dataOffset;
        // meta.bin_feature[55:48] = hdr.tcp.flags;
        // meta.bin_feature[47:32] = hdr.tcp.window;
        meta.bin_feature[47:32] = meta.tcp_window;
        // modify header for test
        // hdr.ipv4.hdrChecksum = 0x2;
    }
    action ac_parse_udp_feature() {
        // meta.bin_feature[67:52] = hdr.udp.srcPort;
        // meta.bin_feature[83:68] = hdr.udp.dstPort;
        // meta.bin_feature[31:16] = hdr.udp.length_;
        meta.bin_feature[31:16] = meta.udp_length;
        // modify header for test
        // hdr.ipv4.hdrChecksum = 0x3;
    }
    action ac_parse_port_feature() {
        meta.bin_feature[111:96] = meta.srcport;
        meta.bin_feature[95:80] = meta.dstport;
    }
    action ac_parse_bin_feature() {
        ac_parse_ip_feature();
        ac_parse_tcp_feature();
        ac_parse_udp_feature();
        ac_parse_port_feature();
    }

    @pragma stage 0
    table parse_bin_feature{
        actions = {
            ac_parse_bin_feature;
        }
        default_action = ac_parse_bin_feature;
    }

    // action: decide forward port
    action ac_packet_forward(macAddr_t dstAddr, PortId_t port){
        // ig_tm_md.ucast_egress_port = port;
        ig_tm_md.ucast_egress_port = 189;
        hdr.ethernet.dstAddr = dstAddr;
    }
    action default_forward() {
        ig_tm_md.ucast_egress_port = 189;
        hdr.ethernet.dstAddr = 0x000000020209;
    }
    @pragma stage 1
    table tb_packet_cls {
        key = {
            meta.bin_feature: ternary;
        }
        actions = {
            ac_packet_forward;
            default_forward;
        }
        default_action = default_forward();
        size = 6000;
    }

    

    apply {
        // stage 0 concat binary feature
        parse_bin_feature.apply();

        // stage 1 classification
        tb_packet_cls.apply();

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


