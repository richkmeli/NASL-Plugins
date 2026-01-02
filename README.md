# NASL-Plugins

Collection of security testing plugins written in NASL (Nessus Attack Scripting Language).

## About NASL

NASL is a scripting language designed for the Nessus security scanner. It provides a framework for writing security tests and vulnerability assessments.

## Available Plugins

### Network Testing
- **Port_Checker.nasl** - Connects to specific TCP ports and retrieves service banners
- **FTP_Test.nasl** - Tests FTP service connectivity and anonymous authentication

### Attack Simulation
- **CRE_attack.nasl** - Exploits Apache vulnerabilities for remote code execution
- **Teardown.nasl** - Cleanup and teardown operations

### Packet Manipulation
- **Forging_Packet_IP.nasl** - IP packet forging techniques
- **Forging_Packet_TCP_reset_attack.nasl** - TCP reset attack implementation
- **Forging_Packet_UDP_MalformedDNS.nasl** - Malformed DNS packet generation

## Usage

These plugins are designed to be used with the Nessus security scanner. Each plugin includes:
- Script metadata and categorization
- Dependency management
- Interactive prompts for configuration
- Detailed output and logging

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Riccardo Melioli

## Disclaimer

These tools are for educational and authorized security testing purposes only. Use responsibly and only on systems you own or have explicit permission to test.
