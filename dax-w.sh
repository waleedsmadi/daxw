#!/bin/bash
# dax-w is a tool for automate target reconnaissance tasks — specifically subdomain enumeration, URL/link enumeration for a given domain, and domain analysis.
# It also produces human-readable HTML reports and leverages well-known, widely used tools.


# Author: Waleed Ibrahim Smadi
# Date: 2025/10/16
# Version: 1.0.0



SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
CURRENT_DIR=$(dirname "$SCRIPT_PATH")

source "${CURRENT_DIR}/functions.lib"
source "${CURRENT_DIR}/subs_scan_functions.lib"
source "${CURRENT_DIR}/urls_scan_functions.lib"
source "${CURRENT_DIR}/reports.lib"
source "${CURRENT_DIR}/settings.lib"
source "${CURRENT_DIR}/domain_info.lib"
source "${CURRENT_DIR}/install_tools.lib"






############ For single flags ############
MAIN_ACTION="$1"
shift 1

if [[ "$MAIN_ACTION" = "-install" || "$MAIN_ACTION" = "--install" ]]; then
	if [[ "$#" -gt 0 ]]; then
		echo -e "\e[31mYou should write -install only to install all tools\e[0m"
		exit 1
	fi
	install_tools
	exit 0
	

elif [[ "$MAIN_ACTION" = "-show-tools" || "$MAIN_ACTION" = "--show-tools" ]]; then
	if [[ "$#" -gt 0 ]]; then
		echo -e "\e[31mYou should write -show-tools only to show tools\e[0m"
		exit 1
	fi
	show_tools
	exit 0
	


	
elif [[ "$MAIN_ACTION" = "-h" || "$MAIN_ACTION" = "-help" || "$MAIN_ACTION" = "--help" ]]; then

	if [[ "$#" -gt 0 ]]; then
		echo -e "\e[31mYou should write -h or -help only to show help message\e[0m"
		exit 1
	fi
	
	help_message
	exit 0
	


elif [[ "$MAIN_ACTION" != "subs" && "$MAIN_ACTION" != "urls" ]]; then
	echo -e "\e[31mError: first arg should be exist ('subs' or 'urls')\e[0m"
	exit 1
fi













############ Options for 'urls' and 'subs' ############

DOMAIN_OPT=""
PATH_LIST_OPT=""
URL_OPT=""
SPECIFIC_NAME_DIR=""
MULTI_OPT=()
TOOLS_OPT=()






while getopts "d:l:u:n:mt" OPT; do

	case "$OPT" in
		d)
			DOMAIN_OPT="$OPTARG"
			;;


		l)
			PATH_LIST_OPT="$OPTARG"
			;;
			
		
		u)
			URL_OPT="$OPTARG"
			;;
		
		n)
			SPECIFIC_NAME_DIR="$OPTARG"
			;;


		
		m)
			temp_arr=("${@:$OPTIND}")
		
			for i in "${temp_arr[@]}"; do
			
				if [[ "$i" == -* ]]; then
					break
				fi
			MULTI_OPT+=("$i")
			shift
			done
			;;
		
		t)
		
			temp_arr=("${@:$OPTIND}")
		
			for i in "${temp_arr[@]}"; do
				
				if [[ "$i" == -* ]]; then
					break
				fi
				TOOLS_OPT+=("$i")
				shift
			done
			;;
		*)
			echo -e "\e[31mError: \e[0mUnkowen option! use -h or -help!"
			exit 1
			
	esac

	
done




# ======================== Handling 'subs' options (subdomains enumeration) ==========================
if [[ "$MAIN_ACTION" == "subs" ]]; then


	# Check if all tool exist!
	if check_tools; then
		echo -e "\e[31mError: There are required tools dont exit!\e[0m\n\n\n"
		display_uninstalled_tools
		exit 1
	fi
	
	
	# Dont run with -u in subs
	if [[ -n "$URL_OPT" ]]; then
		echo -e "\e[31mError: \e[0m-u it works with \e[31m'urls'\e[0m! use \e[31m-h\e[0m to help."
		exit 1
	fi
	
	
	# Handling single domain logic -d
	if [[ -n "$DOMAIN_OPT" ]]; then


		#  just one of (-d, -m, -l) must be exist!
		if [[ -n "$MULTI_OPT"  || -n "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select domain with just \e[31m-d\e[0m or multi domains with \e[31m-m\e[0m or list of domains with \e[31m-l\e[0m"
			exit 1
		fi
		


		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
			DOMAIN="$DOMAIN_OPT"
	      		creating_dirs
			analyze_domain
			print_status
	      		DOMAIN_WITHOUT_TLD="$(remove_tld)" # Remove the TLD
			subs_full_scan
		else
			# the allowed tools with -t option in 'subs' 
			ALLOWED_TOOLS=(sublist3r-passive sublist3r-active amass-passive amass-active subfinder assetfinder gobuster crt)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"

			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			
			# Use the Specific tools that user select
			DOMAIN="$DOMAIN_OPT"
	      		creating_dirs
			analyze_domain
			print_status
	      		DOMAIN_WITHOUT_TLD="$(remove_tld)" # Remove the TLD
	      		subs_specific_scan "$TOOLS_OPT"
			
		fi
			
			

	
	# Handling multi domains logic -m
	elif (( "${#MULTI_OPT[@]}" > 0 )); then
	
		#  just one of (-d, -m, -l) must be exist!
		if [[ -n "$DOMAIN_OPT"  || -n "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select domain with just \e[31m-d\e[0m or multi domains with \e[31m-m\e[0m or list of domains with \e[31m-l\e[0m"
			exit 1
		fi
		
		
		# -m option Must has multi domains!
		if (( "${#MULTI_OPT[@]}" == 1 )); then
			echo -e "\e[31mError: \e[0mYou must select 2 or more domains with \e[31m-m\e[0moption! use \e[31m-d\e[0moption to use one domain!"
			exit 0
		fi
		
		
		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
		
			for d in "${MULTI_OPT[@]}"; do
				DOMAIN="$d"
	      			creating_dirs
				analyze_domain
				print_status
	      			DOMAIN_WITHOUT_TLD="$(remove_tld)" # Remove the TLD
				subs_full_scan
			done
		else
			# the allowed tools with -t option in 'subs' 
			ALLOWED_TOOLS=(sublist3r-passive sublist3r-active amass-passive amass-active subfinder assetfinder gobuster crt)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Use the Specific tools that user select
			for d in "${MULTI_OPT[@]}"; do
				DOMAIN="$d"
	      			creating_dirs
				analyze_domain
				print_status
	      			DOMAIN_WITHOUT_TLD="$(remove_tld)" # Remove the TLD
				subs_specific_scan "$TOOLS_OPT"
			done
		fi
		





	# Handling list of domains.txt logic -l
	elif [[ -n "$PATH_LIST_OPT" ]]; then
	
		
		#  just one of (-d, -m, -l) must be exist!
		if [[ -n "$DOMAIN_OPT"  || -n "$MULTI_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select domain with just \e[31m-d\e[0m or multi domains with \e[31m-m\e[0m or list of domains with \e[31m-l\e[0m"
			exit 1
		fi
		
		
		
		# Check if the file is exist!
		if [[ ! -e "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mThe path of list is wrong. Or the file does not exist!."
			exit 1
		fi
		
		
		
		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
			
			# open fd 3
			exec 3< "$PATH_LIST_OPT"
			while IFS= read -r -u 3 line || [[ -n "$line" ]]; do
				DOMAIN="$line"
				
				
				# continue if the line in the file is empty
				if [[ -z "$DOMAIN" ]]; then
					continue
				fi
				
				
				creating_dirs
				analyze_domain
				print_status
					
					
				
				# Remove the TLD
				DOMAIN_WITHOUT_TLD="$(remove_tld)"
				subs_full_scan
			done
			
			# close the fd3
			exec 3<&-
			
				
		else
			# the allowed tools with -t option in 'subs' 
			ALLOWED_TOOLS=(sublist3r-passive sublist3r-active amass-passive amass-active subfinder assetfinder gobuster crt)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# open fd 3
			exec 3< "$PATH_LIST_OPT"
			while IFS= read -r -u 3 line || [[ -n "$line" ]]; do
				DOMAIN="$line"
				
				
				# continue if the line in the file is empty
				if [[ -z "$DOMAIN" ]]; then
					continue
				fi
				
				
				creating_dirs
				analyze_domain
				print_status
					
					
				
				# Remove the TLD
				DOMAIN_WITHOUT_TLD="$(remove_tld)"
				subs_specific_scan "$TOOLS_OPT"
			done
			
			# close the fd3
			exec 3<&-
		fi
		
	else
		echo -e "\e[31mError: \e[0mUnkowen option with \e[31m'subs'\e[0m use \e[31m-h\e[0m or \e[31m-help\e[0m"
		exit 1
	fi
			
fi
# ========================// End Handling 'subs' options (subdomains enumeration) //==========================


















# ======================== Handling 'urls' options (urls enumeration) ==========================
if [[ "$MAIN_ACTION" == "urls" ]]; then

	# Check if all tool exist!
	if check_tools; then
		echo -e "\e[31mError: There are required tools dont exit!\e[0m\n\n\n"
		display_uninstalled_tools
		exit 1
	fi
	
	
	
	# Dont run with -d in urls
	if [[ -n "$DOMAIN_OPT" ]]; then
		echo -e "\e[31mError: \e[0m-d it works with \e[31m'subs'\e[0m! use \e[31m-h\e[0m to help."
		exit 1
	fi


	# Handling single url logic -u
	if [[ -n "$URL_OPT" ]]; then


		#  just one of (-u, -m, -l) must be exist!
		if [[ -n "$MULTI_OPT"  || -n "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select url with just \e[31m-u\e[0m or multi urls with \e[31m-m\e[0m or list of urls with \e[31m-l\e[0m"
			exit 1
		fi
		
		
		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
			URL="$URL_OPT"
			DOMAIN="$(remove_http)"
	      		creating_dirs
			analyze_domain
			print_status
			urls_full_scan
			
			
		else
			# the allowed tools with -t option in 'url' 
			ALLOWED_TOOLS=(gau dirsearch katana ffuf waymore)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"

			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			
			# Use the Specific tools that user select
			URL="$URL_OPT"
			DOMAIN="$(remove_http)"
	      		creating_dirs
			analyze_domain
			print_status
			urls_specific_scan
	      	fi
		


	# Handling multi urls logic -m
	elif (( "${#MULTI_OPT[@]}" > 0 )); then
	
		#  just one of (-u, -m, -l) must be exist!
		if [[ -n "$URL_OPT"  || -n "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select url with just \e[31m-u\e[0m or multi urls with \e[31m-m\e[0m or list of urls with \e[31m-l\e[0m"
			exit 1
		fi
		
		

		
		
		# -m option Must has multi urls!
		if (( "${#MULTI_OPT[@]}" == 1 )); then
			echo -e "\e[31mError: \e[0mYou must select 2 or more link with \e[31m-m\e[0moption! use \e[31m-u\e[0moption to use one domain!"
			exit 0
		fi
		
		
		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
		
			for u in "${MULTI_OPT[@]}"; do
				URL="$u"
				DOMAIN="$(remove_http)"
		      		creating_dirs
				analyze_domain
				print_status
				urls_full_scan
			done
		else
			# the allowed tools with -t option in 'url' 
			ALLOWED_TOOLS=(gau dirsearch katana ffuf waymore)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Use the Specific tools that user select
			for u in "${MULTI_OPT[@]}"; do
				URL="$u"
				DOMAIN="$(remove_http)"
		      		creating_dirs
				analyze_domain
				print_status
				urls_specific_scan
			done
		fi





	# Handling list of links.txt logic -l
	elif [[ -n "$PATH_LIST_OPT" ]]; then
		
		#  just one of (-d, -m, -l) must be exist!
		if [[ -n "$URL_OPT"  || -n "$MULTI_OPT" ]]; then
			echo -e "\e[31mError: \e[0mYou must select url with just \e[31m-u\e[0m or multi urls with \e[31m-m\e[0m or list of urls with \e[31m-l\e[0m"
			exit 1
		fi
		
		
		
		# Check if the file is exist!
		if [[ ! -e "$PATH_LIST_OPT" ]]; then
			echo -e "\e[31mError: \e[0mThe path of list is wrong. Or the file does not exist!."
			exit 1
		fi
		
		
		
		# Means use full_scan
		if [[ "${#TOOLS_OPT[@]}" == 0 ]]; then
			
			# open fd 3
			exec 3< "$PATH_LIST_OPT"
			while IFS= read -r -u 3 line || [[ -n "$line" ]]; do
				URL="$line"
				
				
				# continue if the line in the file is empty
				if [[ -z "$URL" ]]; then
					continue
				fi
				
				
	      			DOMAIN="$(remove_http)"
	      			creating_dirs
	      			analyze_domain
	      			print_status
	      			urls_full_scan
			done
			
			# close the fd3
			exec 3<&-


		else
			# the allowed tools with -t option in 'url' 
			ALLOWED_TOOLS=(gau dirsearch katana ffuf waymore)
			
			
			# Check if the number of tools that user select is greater than allowed tools!
			check_size_user_tools "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# Check if the user wrote the tools right
			is_input_tools_valid "${TOOLS_OPT[@]}" "${ALLOWED_TOOLS[@]}"
			
			
			# open fd 3
			exec 3< "$PATH_LIST_OPT"
			while IFS= read -r -u 3 line || [[ -n "$line" ]]; do
				URL="$line"
				
				
				# continue if the line in the file is empty
				if [[ -z "$URL" ]]; then
					continue
				fi
				
				
	      			DOMAIN="$(remove_http)"
	      			creating_dirs
	      			analyze_domain
	      			print_status
	      			urls_specific_scan
			done
			
			# close the fd3
			exec 3<&-
		fi	
		
	
	
	else
		echo -e "\e[31mError: \e[0mUnkowen option with \e[31m'urls'\e[0m use \e[31m-h\e[0m or \e[31m-help\e[0m"
		exit 1
	fi
	
		

fi
