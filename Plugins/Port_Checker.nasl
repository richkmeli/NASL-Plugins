
if(description)	{
	script_name(english:"Port-Checker");
	script_summary(english:"connects on remote to specific tcp port and return its banner");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script was written by Riccardo Melioli");
	script_dependencies("find_service.nes");
	exit(0);
}

port = prompt("Which is the port to be scanned? ");

if(get_port_state(port)) {
	soc = open_sock_tcp(port);
	if(soc) {
	    	data = recv(socket:soc, length:1024);
		display("Port ", port, " is open  ||| banner: ", data, "\n");
		close(soc);
	}else{
		display("Port ", port, " is close\n");	
	}
}