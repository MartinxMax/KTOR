#!/bin/bash
# Maptnh@S-H4CK13

GREEN="\e[32m"
CYAN="\e[36m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"
WHITE="\e[97m"
BLUE="\e[34m"


PORT_RANGE_START=1
PORT_RANGE_END=65535
PARALLEL=50 
PORTS_TO_SCAN=(80 8080 443) 

timestamp=$(date +%F-%H%M%S)
log_file="/tmp/http-$timestamp.txt" 


echo -e "${WHITE}J??J?JJJJJJJJJJJYYYYYYYYYYYYYY5YYYYYY55555555555YYY555P5555PP55PP5P5PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
echo -e "${WHITE}JJJJJJJYYYJJYYYYYYYYYYYYY5Y5Y555555555555555YJ7!~~~~!?Y5PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPG"
echo -e "${WHITE}JJJJJYYYYYYYYYYYYYYYYY5Y555555555555555555Y7!~^^:.:^^~!!J5PPPPPPPPPPPPPPPPPPPPPPPPPPPGPGPGPGPGGGGGGG"
echo -e "${WHITE}JYYYYYYYYYYYYYYY55555555555555555555P5PP5?!~~^^:. ..:^~~!!YPPPPPPPPPPPPPPPPPPPGPGGPPGGGPGGGGGGGGGGGG"
echo -e "${WHITE}YYYYYYYYYY5Y555555555555555555555PPPPPPPJ77!^~^.. ..:~^~77?5GPPGPPGGPPPPGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
echo -e "${WHITE}YYYY55555555555555555555PPPPPPP5PPPPPPP577!^~~:.   .:~~^^7!YGPGGPGGGGGPGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
echo -e "${WHITE}555555555555555555PP5PPPPPPPPPPPPPPPPPP7!7~~~^^:::.:^^~!~!775GPGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
echo -e "${WHITE}555555555555PP5PPPPPPPPPPPPPPPPPPPPPPG?~7~~^:..     ...:^~7!7PGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
echo -e "${WHITE}55555555PPPPPPPPPPPPPPPPPPPPPPPPPPPPP5~:.                 .:^JGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGBGGB"
echo -e "${WHITE}5PPPPPPPPPPPPPPPPPPPPPPGGGGPGGPGGGGPGJ                       !GGGGGGGGGGGGGGBGGGGGGGGBBBBBBBBBBBBBBB"
echo -e "${BLUE}!!77777777777777777777777777777777777~                       :7?7777777??777?777???7????????????????"
echo -e "${BLUE}~^~~~~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^                       :~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^                       :~~!!!!~~~~~~~~~!~~!!~~~~!~~~~~~!!!~!!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^::..                      ..:^^~~!!~~~~~~~~~~!!~~!!!!~!!!!!~!!!!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^:....  ..                    .  ....:^~~!~~~~~!!!~~~!!!!!!~!!!!!!!~!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~~^:..: .. ....                 ....... ...::~~~~!!!!!!!~!!!!!!!~!!!!!!~!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~~:... .. .. ...                 ......  . ...:^!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~~:....  . .......               ..... .    . ...^!!!!~!!~!!~!!!!!!!!!!!!!!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~~~~::  .     ......                 . :. .     .  .:^~!!!~!!!!!!!!!!!!!!!!!!!!"
echo -e "${BLUE}~~~~~~~~~~~~~~~~~~~~~~!^:. .        ..:..                 . :. .        ..::~!!!!!!!!!!!!!!!!!!!!!!!"
echo -e "${RED}!!!!!!!!!!!!!!!!!!!!!!~:..          . :.     .       .      :...         ...^!!!!!!!!!!!!!!!!!!!!!!!"
echo -e "${RED}777777777777777777777!^:..          ..:.      .     ..   .  :..          ..:^~7?77777????77?????????"
echo -e "${RED}77777777777777777777!^:.:.            :.  .    .   .     .  :.            ..:^~7??77?7?????????7????"
echo -e "${RED}7777777777777777777!^::...            ..  .     . .     .. .:            ....:^!7???7?77????????????"
echo -e "${RED}7777777777777777777^:::...............::....................:................::^!???77??7???????????"
echo -e "${RED}777777777777777777^.                                                           .:!?7????????????????"
echo -e "${RED}77777777777777777^:.                                                           .::7?????????????????"
echo -e "${RED}77777777777777777~^:                                                           .^^7?????????????????"
echo -e "${RED}77777777777777777!^:                                                           .:~??????????????????"
echo -e "${RED}7777777777777777777^                                                           :!????7??7???????????"
echo -e "${RED}777777777777777777?7                                                           ~??????7?????????????"
echo -e "${GREEN}            Maptnh@S-H4CK13           https://github.com/MartinxMax          KTOR     "


usage() {
    echo -e "${CYAN}Usage: $0 [-t THREADS] [-i INTERFACE] [-l] [-p PORTS] [-h]${RESET}"
    echo -e "  -t THREADS    Set the number of threads (default: 50)"
    echo -e "  -i INTERFACE  Specify the network interface for scanning"
    echo -e "  -l            Scan local ports"
    echo -e "  -p PORTS      Specify ports to scan (e.g., 1,2,3 or all for 1-65535)"
    echo -e "  -h            Show this help message"
}


is_docker() {
    [ -f /.dockerenv ] || [ -d /sys/fs/cgroup/docker ]
}


get_ip_subnet() {
    local iface=$1
    ip addr show "$iface" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | cut -d. -f1-3
}


scan_live_hosts() {
    local subnet=$1
    local temp_file="/tmp/host"
    > "$temp_file"

    for ip in {1..255}; do
        (
            ping -c 1 -W 1 "$subnet.$ip" &>/dev/null
            if [ $? -eq 0 ]; then
                echo "$subnet.$ip" >> "$temp_file"
            fi
        ) &

        [ $(jobs -r -p | wc -l) -ge "$PARALLEL" ] && wait -n
    done
    wait

    if [ -s "$temp_file" ]; then
        mapfile -t alive_ips < "$temp_file"
        echo -e "${CYAN}[+] Alive hosts: [$(echo "${alive_ips[@]}" | tr ' ' ' ')]${RESET}"
    else
        echo -e "${RED}[-] No live hosts found.${RESET}"
        exit 1
    fi
}

check_http_service() {
    local ip=$1
    local port=$2
    local html_content title http_response

    html_content=$(curl -s -m 1 "http://$ip:$port" | tr -d '\0') 
    if [ $? -eq 28 ]; then
        echo -e "${RED}[-] HTTP service on $ip:$port timed out.${RESET}"
        return
    fi

    title=$(echo "$html_content" | grep -oP '(?<=<title>)(.*?)(?=</title>)')
    http_response=$(curl -s -o /dev/null -w "%{http_code}" -m 1 "http://$ip:$port")

    if [ "$http_response" -eq 200 ]; then
        echo -e "${GREEN}[+] HTTP service is up on $ip:$port [$title] ${RESET}"
        echo "$ip:$port - $title" >> "$log_file"  
    else
        echo -e "${RED}[-] HTTP service is not available on $ip:$port${RESET}"
    fi
}

scan_ports() {
    local ip=$1
    > "/tmp/$ip"
    local job_count=0

    for port in "${PORTS_TO_SCAN[@]}"; do
        (
            nc -zv -w 1 "$ip" "$port" &>/dev/null
            if [ $? -eq 0 ]; then
                echo "$port" >> "/tmp/$ip"
            fi
        ) &

        job_count=$((job_count+1))
        if [ "$job_count" -ge "$PARALLEL" ]; then
            wait -n
            job_count=$((job_count-1))
        fi
    done
    wait
}

cleanup() {
    rm -f /tmp/host
    for ip in "${alive_ips[@]}"; do
        rm -f "/tmp/$ip"
    done
}

local_scan_ports() {
    local job_count=0 
    for port in "${PORTS_TO_SCAN[@]}"; do
        (
            nc -zv -w 1 127.0.0.1 "$port" &>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}[+] Local port $port is open${RESET}"
                check_http_service "127.0.0.1" "$port"
            fi
        ) &
        ((job_count++))
        if [ "$job_count" -ge "$PARALLEL" ]; then
            wait -n
            ((job_count--))
        fi
    done
    wait
}

while getopts "t:i:lhp:" opt; do
    case $opt in
        t) PARALLEL=$OPTARG ;;
        i) iface=$OPTARG ;;
        l) local_scan=true ;;
        p) 
            if [ "$OPTARG" == "all" ]; then
                PORTS_TO_SCAN=($(seq 1 65535))
            else
                IFS=',' read -r -a PORTS_TO_SCAN <<< "$OPTARG"
            fi
            ;;
        h) usage; exit 0 ;;
        *) usage; exit 0 ;;
    esac
done

if [ "$local_scan" == true ]; then
    echo -e "${CYAN}[!] Scanning local ports...${RESET}"
else  
    if [ -z "$1" ]; then  
        usage
        exit 0
    else  
        echo -e "${CYAN}[!] Scanning network for hosts in $iface...${RESET}"
        local_scan=false 
    fi
fi

if is_docker; then
    echo -e "${CYAN}[!] Current environment is Docker.${RESET}"
else
    echo -e "${CYAN}[!] Current environment is not Docker.${RESET}"
fi

if [ "$local_scan" = true ]; then
    local_scan_ports
    echo -e "${CYAN}[!] Local port scanning completed.${RESET}"
    exit 0
fi

echo -e "${CYAN}[*] Getting subnet for interface $iface...${RESET}"
subnet=$(get_ip_subnet "$iface")
echo -e "${CYAN}[+] Subnet for $iface: $subnet.0/24${RESET}"

echo -e "${CYAN}[*] Scanning live hosts in $subnet.0/24...${RESET}"
scan_live_hosts "$subnet"

for ip in "${alive_ips[@]}"; do
    echo -e "${CYAN}[*] Scanning ports for $ip...${RESET}"
    scan_ports "$ip"

    if [ -s "/tmp/$ip" ]; then
        open_ports=$(cat "/tmp/$ip")
        for port in $(echo "$open_ports" | tr ',' ' '); do
            check_http_service "$ip" "$port"
        done
    fi
done

cleanup
echo -e "${CYAN}[!] Cleanup completed.${RESET}"
echo -e "${CYAN}[+] HTTP service log saved to: $log_file${RESET}"
