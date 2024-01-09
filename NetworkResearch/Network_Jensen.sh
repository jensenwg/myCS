#!/bin/bash

# ============================ Stage 1 =================================
# Prerequisite update before installing required applications.
function getUpdate()
{
	echo "[!] Initiating update ..."
	apt-get update -y
	echo "[#] Update completed."
}

function checkApp ()
{
	Cond=$(dpkg -l | grep -E '^ii' | grep -w "$1 " | awk '{print$2}')
	if [ "$1" == "$Cond" ]
	then
		echo "[#] $1 is already installed."
	else
		_app=$1
		echo "[X] $_app not yet installed. Commencing installation..."
		instApp $_app
		echo "[#] $_app installation completed."
	fi
}

function checkNipe ()
{
	App=tor
	F=nipe.pl
	
	Condition03=$(dpkg -l | grep -E '^ii' | grep -w "$App " | awk '{print$2}')
	File1=$(find /home -type f -name $F)
	if [ ! -z $File1 ] && [ "$App" != "$Condition03" ]
	# Installation status for Tor is required in case Nipe didn't trigger installation for Tor.
	then
		_app=$App
		echo "[#] Nipe already installed."
		echo "[X] $_app not yet installed. Commencing installation..."
		instApp $_app
		echo "[#] $_app installation completed."
	elif [ -z $File1 ] && [ "$App" == "$Condition03" ]
	then
		_app=$App
		echo "[X] Nipe not yet installed. Commencing installation..."
		instNipe
		echo "[#] Nipe installation completed."
		echo "[#] $_app is already installed."
	elif [ -z $File1 ] && [ "$App" != "$Condition03" ]
	then
		_app=$App
		echo "[X] Nipe not yet installed."
		echo "[X] $_app not yet installed."
		echo "Commencing installation Nipe & $_app..."
		instNipe
		echo "[#] Nipe installation completed."
		echo "[#] $_app installation completed."
	else
		echo "[#] Nipe is already installed."
		echo "[#] $App is already installed."
	fi
}

# Main function to initiate installation for targeted application
function instApp()
{
	apt-get install -y $1
}

# Sub Main function for installing Nipe & Tor applications
function instNipe()
{
	git clone https://github.com/htrgouvea/nipe
	cd nipe && pwd
	yes | cpan install Try::Tiny Config::Simple JSON
	perl nipe.pl install
	cd .. && pwd	
}

getUpdate
checkNipe
checkApp geoip-bin
checkApp sshpass

# ========================= Stage 1 Ended ==============================

# ============================ Stage 2 =================================
# Check the current network connection is anonymous.

function startNipe ()
{
	currStat=$(perl nipe.pl status | grep Status | awk '{print$3}')
	if [ -z $currStat ]
	then 
		perl nipe.pl restart
	elif [ "$currStat" == "false" ]
	then
		perl nipe.pl start
	fi
}

function NipeStatus ()
{
	anonStatus=$(perl nipe.pl status | grep Status | awk '{print$3}')
	if [ "$anonStatus" != "true" ]
	then
		echo "[X] You are not anonymous ..  Aborting remote operation."
		exit
	else
		echo -e "[*] You are anonymous .. Connecting to the remote Server.\n"
		spoofedIP=$(curl -s ifconfig.io)
		country=$(geoiplookup $spoofedIP | awk -F', ' '{print$2}')
		echo "[*] Your Spoofed IP address is: $spoofedIP, Spoofed country: $country"
	fi
}

cd nipe
startNipe
NipeStatus

# ========================= Stage 2 Ended ==============================

# ============================ Stage 3 =================================
# Read user input for target URL/IP, check remote server status, 
# execute whois & nmap on target URL/IP before locally save these data.
# Each activity via remote server will be logged at /var/log/nr.log

function newLog ()
{
	targetLogFile=$(ls /var/log | grep -w nr.log)
	if [ "$targetLogFile" != "nr.log" ]
	then
		touch $logFilePath
		chown kali:kali $logFilePath
	fi
}

function setTarget ()
{
	echo -n "[?] Specify a Domain/IP address to scan: "
	read targetURLIP
}

function logWhois ()
{
	echo `date`" [*] whois data collected for: $targetURLIP"  >> $logFilePath
}

function logNmap ()
{
	echo `date`" [*] Nmap data collected for: $targetURLIP" >> $logFilePath
}

function remoteServer ()
{
	echo -e "\n[*] Connecting to Remote Server:"
	currUptime=$(sshpass -p 'tc' ssh tc@192.168.215.4 -o StrictHostKeyChecking=no -o LogLevel=ERROR "uptime")
	echo "Uptime: $currUptime"
	remoteIP=$(sshpass -p 'tc' ssh tc@192.168.215.4 -o StrictHostKeyChecking=no -o LogLevel=ERROR "curl -s ifconfig.io")
	echo "IP Address: $remoteIP"
	echo "Country: $(geoiplookup $remoteIP | awk -F', ' '{print$2}')"
}

function getWhoIS ()
{
	echo -e "\n[*] Whoising victim's address:"
	fileWhois=whois_$targetURLIP
	sshpass -p 'tc' ssh tc@192.168.215.4 -o StrictHostKeyChecking=no -o LogLevel=ERROR "whois $targetURLIP" > ./$fileWhois
	logWhois
	fileWhoisPath=$(find /home -type f -name $fileWhois)
	echo "[@] Whois data was saved into $fileWhoisPath."
}

function scanNmap ()
{
	echo -e "\n[*] Scanning victim's address:"
	fileNmap=nmap_$targetURLIP
	sshpass -p 'tc' ssh tc@192.168.215.4 -o StrictHostKeyChecking=no -o LogLevel=ERROR "nmap $targetURLIP" > ./$fileNmap
	logNmap
	fileNmapPath=$(find /home -type f -name $fileNmap)
	echo "[@] Nmap scan was saved into $fileNmapPath."
}

logFilePath=/var/log/nr.log
newLog

setTarget
remoteServer
getWhoIS 
scanNmap 

# ========================= Stage 3 Ended ==============================
