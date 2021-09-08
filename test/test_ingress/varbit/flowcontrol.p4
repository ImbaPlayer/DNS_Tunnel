 /* -*- P4_16 -*- */

/*
 * Copyright (c) pcl, Inc.
 *
 *
 *Author：dgl
 */
 // test for varbit in ip options




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

header ipv4_options_h {
    varbit<320> options;
}

header dns_domain_h {
    varbit<2048> dns_tomain;
    // varbit<16384> dns_tomain;
}

// label length
header dns_q_label_len_t {
    bit<8> label_len;
}

header domain_byte_t {
    bit<8> domain_byte;
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


struct my_ingress_metadata_t {
    bit<4> tcp_dataOffset;
    bit<16> tcp_window;
    bit<16> udp_length;
    bit<16> srcport;
    bit<16> dstport;
    bit<112> bin_feature; // total binary feature
    bit<32> packet_in_len;
    bit<8> domain_index;
}

struct my_ingress_headers_t {
    // my change
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    // ipv4_options_h ipv4_options;
    tcp_t       tcp;
    udp_t       udp;
    dns_q_label_len_t q_label_len;
    dns_domain_h total_dns_domain; 
    domain_byte_t[256] domain_list;
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

const bit<16> ETHER_HEADER_LENGTH = 14;
const bit<16> IPV4_HEADER_LENGTH = 20;
const bit<16> ICMP_HEADER_LENGTH = 8;
const bit<16> TCP_HEADER_LENGTH = 20;
const bit<16> UDP_HEADER_LENGTH = 8;


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser IngressParser(packet_in        pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    
    //TofinoIngressParser() tofino_parser;
    ParserCounter() counter;
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
        transition select(hdr.ipv4.ihl) {
            5: dispatch_on_protocol;
            default: accept;
        }
        
   }

   // parse ipv4 options
//    state parse_ipv4_options {
//        pkt.extract(hdr.ipv4_options, ((bit<32>)hdr.ipv4.ihl - 5) << 5);
//        transition dispatch_on_protocol;
//    }

   state dispatch_on_protocol {
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
            53: parse_dns_query;
            default: accept;
        }
    }

    // parse dns query
    state parse_dns_query {
        pkt.extract(hdr.total_dns_domain, 32w2048);
        // pkt.extract(hdr.total_dns_domain, (bit<32>)((bit<4>)hdr.ipv4.totalLen << 3) - 224); // 224: ip_header(20) + udp_header(8)
        // pkt.extract(hdr.total_dns_domain, (bit<32>)((bit<8>)hdr.ipv4.totalLen << 3) - 224);
        transition accept;
    }

    // test domain byte loop
    // state parse_dns_query {
    //     pkt.extract(hdr.q_label_len);
    //     counter.set(hdr.q_label_len.label_len);
    //     // counter.set(8w4);
    //     transition select(counter.is_zero()) {
    //         true: finish_parse_domain;
    //         false: parse_domain_byte;
    //     }
    // }

    // state parse_domain_byte {
    //     pkt.extract(hdr.domain_list.next);
    //     counter.decrement(8w1);
    //     transition select(counter.is_zero()) {
    //         true: parse_dns_query;
    //         false: parse_domain_byte;
    //     }
    // }

    // state finish_parse_domain {
    //     transition accept;
    // }
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
    
    
    action ac_test_index_list() {
        bit<2048> tmp_val;
        tmp_val = hdr.total_dns_domain.dns_tomain;
    }

    table tb_test_index_list {
        // key = {
        //     hdr.total_dns_domain.dns_tomain[10:0]: ternary;
        // }
        actions = {
            ac_test_index_list;
        }
        default_action = ac_test_index_list;
    }

    apply {
        meta.domain_index = 1;
        tb_test_index_list.apply();

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


