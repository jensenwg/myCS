#!/bin/bash
######################################################################
#                       ==== VULNER CHECK ====                       #
######################################################################
# Name   : Jensen Wong                                               #
######################################################################

function addUserPass()
{
	# Allow user to specify one (1) userID file, and one (1) choice to
	# either specify password file, or create a new password list.
	echo -e "###########\nPREPARATION\n###########"
	echo "Key in the path for user list and press 'Enter'."
	read -p "> " user_list
	echo "Key in the path for password list and press 'Enter'."
	echo "Else, just press 'Enter' for new password list."
	read -p "> " password_list

	# Press 'Enter' to create new password list
	if [ -z "$password_list" ]
	then
		password_list="passwords.txt"

		# Check if password file exists & confirm before overwriting
		if [ -f "$password_list" ]
		then
			echo "WARNING! Existing $password_list will be overwritten."
			echo "Press 'Enter' to proceed or 'q' to return to Menu."
			read -p "> " pause
			if [ "$pause" = "q" ] || [ "$pause" = "Q" ]
			then
				echo -e "Halt! Returning to Menu...\n"
				return 1
			fi
		fi

		# Clear the file content before writing new passwords
		truncate -s 0 $password_list
		echo "Enter each password of your choice (separated by spaces):"
		read -p "> " new_passwords        
		for password in $new_passwords
		do
			echo $password >> $password_list
		done    
	fi
}

function checkIPRange()
{
	# Automatically identify the LAN network range
	echo "========================================================"
	echo "Current IP Network Range"
	echo "--------------------------------------------------------"
	my_privateIP=$(ifconfig | grep broadcast | awk '{print $2}')
	echo "Private IP Address     : $my_privateIP"
	my_subnetIP=$(route -n | grep -w U | awk '{print $3}')
	echo "Subnet Mask IP Address : $my_subnetIP"
	my_CIDR=$(netmask -c $my_privateIP/$my_subnetIP | tr -d '[:space:]')
	echo "CIDR IP Address        : $my_CIDR"
	my_LANRange=$(netmask -r $my_CIDR | awk '{print $1}')
	echo "LAN network range      : $my_LANRange"
}

function hostDiscovery
{
	# Automatically scan the current LAN for any live hosts.
	# Then, list out each IP address of the discovered live hosts.
	echo "========================================================"
	echo "Hosts Discovery"
	echo "--------------------------------------------------------"
	echo "Scanning for live host within this network..."
	gatewayIP=$(route -n | grep UG | awk '{print$2}')
	ipList=$(nmap -sn $my_CIDR | grep "Nmap scan report" | grep -v $gatewayIP | awk '{print $5}')
	echo "Scan completed."
	echo "###############"
	echo -e "$ipList"
	echo "###############"
}

function enumHost ()
{
	# Automatically enumerate each live host;
	# scan for open ports and identify potential vulnerabilities.
	echo "========================================================"
	echo "Live Hosts Enumeration"
	echo "--------------------------------------------------------"
	while read -r line
	do
		ip=$(echo $line)
		echo "($ip) Enumerating..."
		nmap --script vuln -sV -p- --open $ip > nmap_vuln_$ip.txt
		echo "Completed => nmap_vuln_$ip.txt"
	done <<< "$ipList"
}

function checkWeakPass()
{
	# Confirming login service before brute force on live hosts.
	# If login service detected, brute force using Hydra.
	# If brute force failed on this service, repeat on next service.
	# If current brute force succeed, stop and check the next live host.
	echo "========================================================"
	echo "Brute Force Initiation"
	echo "--------------------------------------------------------"

	# Set counter for number of devices with weak password
	counterWP=0

	while read -r ip
	do
		echo "Checking IP $ip"

		# Get the open ports and services from respective IP Address
		ports=$(cat nmap_vuln_$ip.txt | grep -w open | grep tcp | awk '{print $1,$3}' | awk -F'/tcp' '{print $1,$2}')

		# Read line by line for port number variable 
		while read -r line
		do
			# Extract the port number and service name from the line
			port=$(echo $line | awk '{print $1}')
			service=$(echo $line | awk '{print $2}')

			# Check for login service before running Hydra
			case "$service" in
				ftp|ssh|mysql)
					svcname=$service
					;;
				netbios-ssn|microsoft-ds)
					svcname="smb"
					;;
				login)
					svcname="rlogin"
					;;
				*)
					# Skip if no open service or not login service
					continue
					;;
			esac

			# Brute Force on current open port/service
			hydra -L $user_list -P $password_list -f -o hydra_$ip.txt -u $ip -s $port -t 4 $svcname > /dev/null 2>&1

			# Check if last output contains valid credentials
			if tail -n 1 hydra_$ip.txt | grep -q "login:"
			then
				echo -e "[WARNING!] Weak password discovered on [$service:$port] for IP $ip.\n"
				counterWP=$(( counterWP + 1 ))
				break 1
			fi			
		done <<< "$ports"
		
		# Print a message when all port scanned with no weak password,
		# or there's no open port/service found.
		if [ -z "$line" ]
		then
			echo -e "Weak password not found in IP $ip.\n"
		fi	
	done <<< "$ipList"
}

# Function to generate a report
function generateReport()
{
	# Calculate total scan time
	scan_time=$((end_time-start_time))
	scan_min=$((scan_time/60))
	scan_sec=$((scan_time%60))
	
	# Calculate total devices discovered
	num_devices=$(echo "$ipList" | wc -l)
	
	echo "========================================================"
	echo "Generating report..."
	echo -e "================ VULNERABILITY REPORT ================\n" > report.txt
	echo "Scanned LAN Network Range       : $my_LANRange" | tee -a report.txt
	echo "Total Scan Time                 : $scan_min minutes $scan_sec seconds" | tee -a report.txt
	echo "Total Devices Found             : $num_devices unit(s)" | tee -a report.txt
	echo "Total Devices with Weak Password: $counterWP unit(s)" | tee -a report.txt
	echo -e "\nDetailed Report:" >> report.txt

	while read -r line
	do
		ip=$(echo $line)
		echo -e "\n==> $ip" >> report.txt
		echo "########################" >> report.txt
		echo "Nmap scan result:" >> report.txt
		echo "########################" >> report.txt
		cat nmap_vuln_$ip.txt >> report.txt
		echo "########################" >> report.txt
		echo "Weak Password Detection:" >> report.txt
		echo "########################" >> report.txt
		if [ -f hydra_$ip.txt ]
		then
			# If file exist, check if login exist.
			if tail -n 1 hydra_$ip.txt | grep -q "login:"
			then
				# Output if login exist.
				cat hydra_$ip.txt | tail -n 1 >> report.txt
			else
				# Output if empty.
				echo "==== Not detected in $ip ==== " >> report.txt
			fi
		else
			# If file does not exist, write "Not detected"
			echo "==== Not detected in $ip ====" >> report.txt
		fi
		echo "########################" >> report.txt
	done <<< "$ipList"
	echo -e "\n=================== END OF REPORT ====================" >> report.txt
	echo "Results saved to report.txt"
}

# Function to display the filtered results based on specific IP address
function displayResults()
{
	echo "Enter an IP address to display the relevant findings:"
	read ip_address
	echo "Relevant findings for $ip_address:"
	cat report.txt | sed -n "/==> $ip_address/,/==>/p" | sed '1d' | sed '$d'
}

# Start the script with selectable menu:
# 1 - To run pentest; 2 - display report; 3 - Exit the script
while true
do
	echo "Enter one of the options below:"
	echo "1. Conduct vulnerability check"
	echo "2. Read the report"
	echo "Q. Quit"
	read -p "Option: " option

	if [ "$option" = "1" ]
	then
		# Func <addUserPass> to specify add userID & Password List.
		addUserPass
		# Return to menu when press 'q'.
		if (( $? == 1 ))
		then
			continue
		fi

		# Set start time in epoch time format
		start_time=$(date +%s)
		echo "========================================================"
		echo "Operation Vulner Penetration Testing - START"
		echo "--------------------------------------------------------"
			
		# Func <checkIPRange> to check for current IP Network Range.
		checkIPRange
		
		# Func <hostDiscovery> to scan all live host(s) within LAN.
		hostDiscovery
		
		# Func <enumHost> to enum live host for potential vulnerability.
		enumHost
		
		# Func <checkWeakPass> to check port for login service.
		# If found, brute force using weak password on targeted host.
		checkWeakPass

		# Set end time in epoch time format.
		end_time=$(date +%s)
		
		# Func <generateReport> to save all results into a report.
		generateReport
		echo "--------------------------------------------------------"
		echo "Operation Vulner Penetration Testing - END"
		echo "========================================================"
	elif [ "$option" = "2" ]
	then
		# Func <displayResults> to display relevant findings.
		displayResults
	elif [ "$option" = "Q" ] || [ "$option" = "q" ]
	then
		echo "Exiting the script..."
		break
	else
		echo "Invalid option. Please try again."
	fi
done
