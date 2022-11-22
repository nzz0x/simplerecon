#!/bin/bash
##########
# 	AUTHOR
#			 nzz0x
#	REQUIRES
#			Installed Packets: subfinder, httpx, nuclei and nuclei-templates
#	HOW TO USE
#			call simpleRecon with a list of domain (at least 1)
#		 	./simpleRecon.sh domain1 domain2 domain3 
#	RETURN
#			A set of reports are genereted in targetDir in order to help the Recon phase
##########

########################################
# CHANGE HERE ACCORDING YOUR ENVIRONMENT
targetDir=~/target/
NUCLEI_TEMPLATES=~/nuclei-templates/
GO_BIN=~/go/bin
########################################

targets=$@
argumentsNumber=$#
# Color variables
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
clear='\033[0m'

checkArgumentsAndSetup(){
	if [ $argumentsNumber -eq 0 ]; then
    	echo -e "${red}At least 1 domain is required!${clear}"
    	exit 1
	fi

	if [ ! -d "$targetDir" ]; then
		mkdir -p $targetDir
	fi

}

doRecon(){
	cd ~
	for target in $targets
	do
		ping -c1 $target 1>/dev/null 2>/dev/null
		SUCCESS=$?
		if [ $SUCCESS -eq 0 ]; then
			findValidSubdomains $target
			scanAllDomainsOf $target
			createRelevantReports $target
		else
		  echo -e "${red}The domain $target seems not to be available${clear}"
		fi
	done
}

findValidSubdomains(){
	echo -e "${green}Looking for available subdomains to ${clear}$1 ${yellow}(its can take some minutes)${clear}"
	targetRawFile=$targetDir$1_raw
	$GO_BIN/subfinder -d "$1" -silent | $GO_BIN/httpx -silent > $targetRawFile	
}

scanAllDomainsOf(){
	targetRawFile=$targetDir$1_raw
	targetNucleiFile=$targetDir$1_nuclei
	echo -e "${green}Running nuclei for each subdomains of${clear} $1"
	$GO_BIN/nuclei -l $targetRawFile -t $NUCLEI_TEMPLATES | tee $targetNucleiFile
}

createRelevantReports(){
	targetNucleiFile=$targetDir$1_nuclei
	grep -v info $targetNucleiFile > $targetNucleiFile'_relevant'
	grep medium $targetNucleiFile > $targetNucleiFile'_medium'
	grep critical $targetNucleiFile > $targetNucleiFile'_critical'
	grep CVE $targetNucleiFile > $targetNucleiFile'_cves'
}


main(){
	ts=$(date +%s%N)
	echo -e "${green}Starting recon...${clear}"
	checkArgumentsAndSetup
	doRecon
	echo -e "${green}Check all generated reports in${clear} ${targetDir}<domain>_*"
	echo "Recon has been done in $((($(date +%s%N) - $ts)/1000000)) ms"
}
main $@
#EOF