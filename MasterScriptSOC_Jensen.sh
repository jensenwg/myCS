#!/bin/bash
###############################################################
#                    ==== SOC CHECKER ====                    #
###############################################################
# Name    : Jensen Wong                                       #
###############################################################

# Check the script meet the requirement to run using sudo privilege 
if [ "$EUID" -ne 0 ]
  then echo "Please run as root or use sudo"
  exit
fi

# List of possible tools to initiate the attack
function toolHydra()
{
	echo "========================================================="
	echo ' _   ___   ______  ____      _'
	echo '| | | \ \ / /  _ \|  _ \    / \'
	echo '| |_| |\ V /| | | | |_) |  / _ \'
	echo '|  _  | | | | |_| |  _ <  / ___ \'
	echo '|_| |_| |_| |____/|_| \_\/_/   \_\'
	echo "---------------------------------------------------------"
	echo "This Hydra tool will attempt a brute force attack on the"
	echo "username and password, and will stop as soon as a valid"
	echo "password is found. The results will be saved in a file"
	echo "named 'hydra_<ip>.txt'."
	echo "========================================================="
	
	# Function to manual or random select IP Address
	selectIP
	
	# Brute Force attack on ssh service & log this task in SOCattack.log
	echo `date '+%Y-%m-%d %H:%M:%S'`" [Hydra] $ip"  >> $logFilePath
	hydra -l kali -p kali -o hydra_$ip.txt -u $ip -s 22 -t 4 ssh > /dev/null 2>&1

	# Check if last output contains valid credentials
	echo "Hydra result for $ip:"
	if tail -n 1 hydra_$ip.txt | grep -q "login:"
	then
		cat hydra_$ip.txt | tail -n 1
	else
		echo "NIL"
	fi			
}

function toolNMap()
{
	echo "========================================================="
	echo "#     # #     #"
	echo "##    # ##   ##   ##   #####"
	echo "# #   # # # # #  #  #  #    #"
	echo "#  #  # #  #  # #    # #    #"
	echo "#   # # #     # ###### #####"
	echo "#    ## #     # #    # #"
	echo "#     # #     # #    # #"
	echo "---------------------------------------------------------"
	echo "This NMap tool will scan all ports on the target machine,"
	echo "attempt to determine the version of the service running"
	echo "on each open port, and only show open ports in the output"
	echo "========================================================="	
	
	# Function to manual or random select IP Address
	selectIP
	
	# Run port scan on targeted server & log this task in SOCAttack.log
	echo `date '+%Y-%m-%d %H:%M:%S'`" [NMap] $ip"  >> $logFilePath
	nmap -sV -p- --open $ip -oN nmap_port_$ip.txt
}

function toolMSF()
{
	echo "========================================================"
	echo '+-+-+-+-+-+-+-+-+-+-+'
    echo '|M|e|t|a|s|p|l|o|i|t|'
    echo '+-+-+-+-+-+-+-+-+-+-+'
	echo "--------------------------------------------------------"
	echo "This Metasploit attack will conduct version scan on"
	echo "common services (i.e. ftp, http, ssh) running in the"
	echo "targeted server. The scan result will be output in .txt."
	echo "========================================================"
	
	# Function to manual or random select targeted IP Address
	selectIP

	# Define the Metasploit scanner module(s) to be loaded
	SCANNER01="auxiliary/scanner/ftp/ftp_version"
	SCANNER02="auxiliary/scanner/http/http_version"
	SCANNER03="auxiliary/scanner/ssh/ssh_version"
	
	# Define output file from Metasploit
	OUTPUT_FILE="msf_output.txt"
	
	# Create metasploit resource script for this scanner
	echo "spool $OUTPUT_FILE
use $SCANNER01
setg RHOSTS $ip
run
use $SCANNER02
run
use $SCANNER03
run
spool off
exit" > msf.rc
	
	# Run msfconsole resource script in quiet mode & log this task.
	echo `date '+%Y-%m-%d %H:%M:%S'`" [MSF] $ip"  >> $logFilePath
	msfconsole -q -r msf.rc
}

function selectIP()
{
	echo "Select one of these options below:"
	echo "1) Choose an IP address"
	echo "2) Randomly select an IP address"
	read -p "Enter your choice (1 or 2): " choice
	
	case $choice in
		1)
			echo "Choose an IP address from the list:"
			select ip in "${ip_addresses[@]}"; do
				echo -e "You selected: $ip\n"
				break
			done
			;;
		2)
			ip=${ip_addresses[$RANDOM % ${#ip_addresses[@]}]}
			echo -e "Randomly selected IP address: $ip\n"
			;;
		*)
			# Exit the script when entering wrong key
			echo "Invalid option selected. Terminating script..."
			exit 1
			;;
	esac
}

# Preparation Stage
# Prep#1: Setup a new log for SOC Attack Simulation in /var/log
logFilePath=/var/log/SOCAttack.log
targetLogFile=$(ls /var/log | grep -w SOCAttack.log)
if [ "$targetLogFile" != "SOCAttack.log" ]
then
	touch $logFilePath
	chown kali:kali $logFilePath
fi

# Start with initial network scanning for live hosts:
# 1. Automatically identify the LAN network range.
my_privateIP=$(ifconfig | grep broadcast | awk '{print $2}')
my_subnetIP=$(route -n | grep -w U | awk '{print $3}')
my_CIDR=$(netmask -c $my_privateIP/$my_subnetIP | tr -d '[:space:]')

# 2. Automatically scan the current LAN for any live hosts.
#    Then, list out each IP address of the discovered live hosts.
echo "Scanning for live host within this network..."
gatewayIP=$(route -n | grep UG | awk '{print$2}')
ipList=$(nmap -sn $my_CIDR | grep "Nmap scan report" | grep -vE "\.1$|\.254$|$gatewayIP" | awk '{print $5}')
# Store each IP Addresses in one array variable.
ip_addresses=($ipList)
echo "Scan completed."

# Set Initial array for "4. Randomized Attack" option
functions=(toolHydra toolNMap toolMSF)

# Start with selectable menu for type of simulated attack:
# 1 - BruteForce-Hydra; 2 - Network Scan-NMap; 3 - Version Scan-MSF;
# 4 - Randomly select one of the simulated attacks.
while true
do
	echo "========================================================="
	echo "Current IP Network Range"
	echo "---------------------------------------------------------"
	echo "CIDR IP Address        : $my_CIDR"
	echo "========================================================="
	echo "Hosts Discovery"
	echo "###############"
	echo -e "$ipList"
	echo "========================================================="
	echo "<< MAIN MENU>>"
	echo "---------------------------------------------------------"
	echo "Select one of the attack options below:"
	echo "1. Hydra – Bruteforce login into SSH"
	echo "2. NMap – Display services with opened ports"
	echo "3. MSF – Retrieve version info and details of the services"
	echo "4. Randomized Attack"
	echo "Q. Quit"
	read -p "Option: " option

	if [ "$option" = "1" ]
	then
		# Func <toolHydra> to bruteforce.
		toolHydra
	elif [ "$option" = "2" ]
	then
		# Func <toolNMap> to scan network for opened port and svc.
		toolNMap
	elif [ "$option" = "3" ]
	then
		# Func <toolMSF> to exploit the vulnerabilities.
		toolMSF
	elif [ "$option" = "4" ]
	then
		# Randomly select any one of the listed attacks above.
		echo "Randomizing attack..."
		indexFunction=$((RANDOM % 3))
		${functions[$indexFunction]}		
	elif [ "$option" = "Q" ] || [ "$option" = "q" ]
	then
		echo "Exiting the script..."
		break
	else
		# Exit the script when entering wrong key
		echo "Invalid input detected. Terminating script..."
		break
	fi
done
