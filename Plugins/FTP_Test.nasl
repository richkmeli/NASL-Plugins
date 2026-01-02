
if(description)	{
	script_name(english:"FTP test");
	script_summary(english:"connects on remote tcp port 21");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script was written by Riccardo Melioli");
	# find_service to find FTP service on other ports
	script_dependencies("find_service.nes");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

include("audit.inc");
include("ftp_func.inc");

# Get FTP service port from Knowledge Base
port = get_kb_item("Services/ftp");
# If not detected by other plugins, test default port
if(!port){	
	port = 21;
}

soc = open_sock_tcp(port);
if(soc)	{
	display("Socket on port: ",port ," opened \n");

	data = recv(socket:soc, length:1024);
	display("FTP is running");
	
	if("FTP" >< data){ 
		 display(" ||| banner: ", data, "\n");
	}else{
		display("\n");
	}

	# HIGH LEVEL FUNCTION - Login as anonymous user
	if(ftp_authenticate(socket:soc, user:"anonymous", pass:"test@example.com")){	
		display("Authentication as anonymous user successful\n");
	}
	
	close(soc);
}else{
	display("Socket on port: ",port ," closed \n");
}

