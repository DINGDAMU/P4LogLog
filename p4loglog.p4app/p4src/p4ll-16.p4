#include <core.p4>
#include <v1model.p4>

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    bit<32> nhop_ipv4;
    bit<32> hash_val1;
    bit<32> count_tot;
    bit<32> current_count;
    bit<32> value;
    bit<16> bucket;
    bit<32> car;
    bit<32> val_buc0;
    bit<32> val_buc1;
    bit<32> val_buc2;
    bit<32> val_buc3;
    bit<32> val_buc4;
    bit<32> val_buc5;
    bit<32> val_buc6;
    bit<32> val_buc7;
    bit<32> val_buc8;
    bit<32> val_buc9;
    bit<32> val_buc10;
    bit<32> val_buc11;
    bit<32> val_buc12;
    bit<32> val_buc13;
    bit<32> val_buc14;
    bit<32> val_buc15;
    bit<32>  buc_sum;
    bit<32> coef;
    bit<32> bEXP;
    bit<8> powerS;
    bit<32> power_sum;
    bit<32> occSlot;
    bit<32> factor;
    bit<32> decimal;
    bit<32> pow;
    bit<32> exp_value;
    bit<32> log_value;
    bit<32> occR1;
    bit<32> occR2;
    bit<32> buc_val;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}

register<bit<32>>(32w3) hash_register;

register<bit<32>>(32w16) hll_register;


control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    action _drop() {
        mark_to_drop();
    }

    action do_expES()  {
        meta.exp_value = (bit<32>)(meta.bEXP >> 10);
        meta.pow = (bit<32>)meta.bEXP - (meta.exp_value << 10);
        meta.decimal = meta.decimal + meta.pow;
        meta.decimal = meta.decimal + 32w1024;
        meta.decimal = meta.decimal - (meta.pow * (32w1024 - meta.pow) >> 11);
        meta.decimal = meta.decimal + (((meta.pow * (32w1024 - meta.pow)>>10) * (32w2048 - meta.pow)>>10) * 32w170 >> 10);
        
     }
    action do_loglog_counting() {
        hll_register.read(meta.val_buc0, (bit<32>)0);
        hll_register.read(meta.val_buc1, (bit<32>)1);
        hll_register.read(meta.val_buc2, (bit<32>)2);
        hll_register.read(meta.val_buc3, (bit<32>)3);
        hll_register.read(meta.val_buc4, (bit<32>)4);
        hll_register.read(meta.val_buc5, (bit<32>)5);
        hll_register.read(meta.val_buc6, (bit<32>)6);
        hll_register.read(meta.val_buc7, (bit<32>)7);
        hll_register.read(meta.val_buc8, (bit<32>)8);
        hll_register.read(meta.val_buc9, (bit<32>)9);
        hll_register.read(meta.val_buc10, (bit<32>)10);
        hll_register.read(meta.val_buc11, (bit<32>)11);
        hll_register.read(meta.val_buc12, (bit<32>)12);
        hll_register.read(meta.val_buc13, (bit<32>)13);
        hll_register.read(meta.val_buc14, (bit<32>)14);
        hll_register.read(meta.val_buc15, (bit<32>)15);
        meta.buc_sum = (bit<32>)(meta.val_buc0 + meta.val_buc1 + meta.val_buc2 + meta.val_buc3 + meta.val_buc4 + meta.val_buc5 + meta.val_buc6 + meta.val_buc7 + meta.val_buc8 + meta.val_buc8 + meta.val_buc9 + meta.val_buc10 + meta.val_buc11 + meta.val_buc12 + meta.val_buc13 + meta.val_buc14 + meta.val_buc15);
            }

    action set_hll_count() {
        /*hash(meta.hash_val1, HashAlgorithm.xxhash64_40, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr}, (bit<32>)((1 << 32) - 1));*/
        /*hash(meta.hash_val1, HashAlgorithm.xxhash64_40, (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol,  hdr.ipv4.identification}, (bit<32>)((1 << 32) - 1));*/
        hash(meta.hash_val1, HashAlgorithm.xxhash64_40, (bit<32>)0, {hdr.ipv4.dstAddr}, (bit<32>)((1 << 32) - 1));
        meta.bucket = (bit<16>)(meta.hash_val1 & 32w0xf);
        meta.value = (meta.hash_val1 >> 4) | ((meta.hash_val1 >> 4) << 1);
        meta.value = meta.value | (meta.value << 2);
        meta.value = meta.value | (meta.value << 4);
        meta.value = meta.value | (meta.value << 8);
        meta.value = meta.value | (meta.value << 16);
        meta.value = (meta.value & 32w0x55555555) + ((meta.value >> 1) & 32w0x55555555);
        meta.value = (meta.value & 32w0x33333333) + ((meta.value >> 2) & 32w0x33333333);
        meta.value = (meta.value & 32w0xf0f0f0f) + ((meta.value >> 4) & 32w0xf0f0f0f);
        meta.value = (meta.value & 32w0xff00ff) + ((meta.value >> 8) & 32w0xff00ff);
        meta.value = (meta.value & 32w0xffff) + ((meta.value >> 16) & 32w0xffff);
        meta.value = 32w32 - meta.value + 32w1;
        hash_register.write((bit<32>)0, (bit<32>)meta.value);
        hash_register.write((bit<32>)1, (bit<32>)meta.bucket);
        hll_register.read(meta.current_count, (bit<32>)meta.bucket);
    }
    action do_update_hll() {
        hll_register.write((bit<32>)meta.bucket, (bit<32>)meta.value);
    }
    table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    table loglog_counting {
        actions = {
            do_loglog_counting;
        }
    }

    table set_hll_table {
        actions = {
            set_hll_count;
        }
        size = 1;
    }
    table update_hll {
        actions = {
            do_update_hll;
        }
    }
    table expES{
        actions = {
            do_expES;
        }
    }
    apply {
        ipv4_lpm.apply();
        set_hll_table.apply();
        if (meta.current_count < meta.value) {
                update_hll.apply();
            }
        loglog_counting.apply();
        meta.bEXP = meta.buc_sum << (bit<8>)(10 - 4);
        expES.apply();
        if (meta.exp_value < 8){
                     meta.powerS = (bit<8>)1<< ((bit<8>)meta.exp_value);
                     meta.power_sum = (bit<32>)meta.powerS;
                 }else if (meta.exp_value < 16 ){
                     meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 8);
                     meta.power_sum = (bit<32>)meta.powerS * (1<<8);
                 }else if (meta.exp_value < 24 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 16);
                     meta.power_sum = (bit<32>)meta.powerS * (1<<16);
                 }else if (meta.exp_value < 32 ){
         meta.powerS =(bit<8>)1<<((bit<8>)meta.exp_value - 24);
                     meta.power_sum = (bit<32>)meta.powerS * (1<<24);
                 }
        meta.power_sum = (meta.power_sum) * meta.decimal;

        meta.coef = meta.power_sum * 16;
        // alpha_m = 0.39701
        // alpha_m << 10 = 406
        meta.car = (meta.coef * 32w406) >> 10;
        meta.car = (meta.car >> 10);
        hash_register.write((bit<32>)2, (bit<32>)meta.car);

    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

