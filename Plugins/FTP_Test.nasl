
if(description)	{
	script_name(english:"FTP test");
	script_summary(english:"connects on remote tcp port 21");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script was written by Riccardo Melioli");
	// find_service per trovare il servizio FTP su eventuali altre porte
	script_dependencies("find_service.nes");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

include("audit.inc");
include("ftp_func.inc");

// Richiediamo al Knowledge Base la porta del servizio FTP
port = get_kb_item("Services/ftp");
// Se non è stata ancora rilevata da altri plugin testiamo il default
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

	// HIGH LEVEL FUNCTION - Log in come utente anonimo
	if(ftp_authenticate(socket:soc, user:"ftp", pass:"richk")){	
		display("Autentication as anonymous user \n");
	}
	
	close(soc);
}else{
	display("Socket on port: ",port ," closed \n");
}

