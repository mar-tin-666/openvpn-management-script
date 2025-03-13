#!/bin/bash

# Terminal text formatting definitions
bold=$(tput bold 2>/dev/null || echo "")
normal=$(tput sgr0 2>/dev/null || echo "")

# Get the script filename
scriptFile=$(basename "$BASH_SOURCE")

# Script to check for updates on GitHub and update the script if a new version is available.
scriptOnGitHub="https://raw.githubusercontent.com/mar-tin-666/openvpn-management-script/refs/heads/main/bash.script/openvpn-mgmt.sh"

# Base OpenVPN configuration directory
openvpnConfigPath="/etc/openvpn"

# Paths to configuration files and directories
serverConfigPrefix=""
serverConfigPath="$openvpnConfigPath/server"
easyRsaPath="$openvpnConfigPath/easy-rsa"
crlPemFile="$easyRsaPath/pki/crl.pem"
openvpnCrlFile="$openvpnConfigPath/crl.pem"
clientProfilesDir="/openvpn-client-profiles"
caCertFile="$easyRsaPath/pki/ca.crt"
taKeyFile="$easyRsaPath/pki/ta.key"
configClientPath="$openvpnConfigPath/ccd"
outputClientPath="$openvpnConfigPath/client-profiles"
removedClientPath="$openvpnConfigPath/client-removed"
baseClientPath="$openvpnConfigPath/client-base"
logsPath="/var/log/openvpn"
reqPath="$easyRsaPath/pki/reqs"
issuedPath="$easyRsaPath/pki/issued"
privatePath="$easyRsaPath/pki/private"

# Ensure required directories exist
for dir in "$configClientPath" "$outputClientPath" "$removedClientPath"; do
    [[ ! -d "$dir" ]] && mkdir -p "$dir"
done

# Script header
cat <<EOF

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
  ${bold}OpenVPN Management Tool v1${normal}
  https://github.com/mar-tin-666/openvpn-management-script
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

EOF

# Check if the script is run as root
if [[ "$EUID" -ne 0 ]]; then
    echo "Error: You must run this script as root."
    exit 1
fi

# Function to display available options
usage() {
    cat <<EOF
 Usage: $scriptFile <command>

 Commands:
  add {profileName} {profileBaseConfig}   - Adds a new client profile.
  remove {profileName}                    - Removes a client profile.
  copy {localUserName}                    - Copies client profiles to the user's home directory.
  check {numberOfDays}                    - Checks certificates expiring within the given number of days.
  list profiles                           - Displays the list of user profiles.
  list configs                            - Displays the list of base configurations.
  info                                    - Shows currently connected users.
  log {username}                          - Displays the login and disconnection history of a user.
  restart                                 - Restarts the OpenVPN service and all servers.
  update                                  - Checks for updates and updates the script.

EOF
    exit 1
}

# Function to check for updates and update the script
checkAndUpdateScript() {
    echo "Checking for updates..."

    # Fetch remote file content
    remoteFileContent=$(curl -s -w "%{http_code}" "$scriptOnGitHub")

    # Extract HTTP status code (last 3 characters of the response)
    httpStatus="${remoteFileContent: -3}"
    remoteFileContent="${remoteFileContent:0:-3}"

    if [[ "$httpStatus" != "200" ]]; then
        echo "Error: Failed to fetch the file from GitHub (HTTP $httpStatus)."
        exit 1
    fi

    # Compare local and remote versions
    if diff -q <(echo "$remoteFileContent") "$scriptFile" >/dev/null; then
        echo "Your script is up to date."
    else
        echo "A new version of the script is available! Do you want to update? (y/n)"
        read -r answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            cp "$scriptFile" "${scriptFile}.bak"  # Backup old version
            echo "$remoteFileContent" > "$scriptFile"
            chmod +x "$scriptFile"  # Ensure the file remains executable
            echo "Update complete! Backup created: ${scriptFile}.bak"
            exit 0  # Terminate script after update
        else
            echo "Update canceled. You are using an outdated version."
        fi
    fi
}

# Function to check certificates expiring soon
checkCertificates() {
    local days="$1"
    echo "Checking certificates expiring within $days days..."

    for certFile in "$issuedPath"/*.crt; do
        [[ ! -f "$certFile" ]] && continue

        expiryDate=$(openssl x509 -enddate -noout -in "$certFile" 2>/dev/null | cut -d= -f2)
        [[ -z "$expiryDate" ]] && echo "Error: Cannot read certificate $certFile" && continue

        expiryTimestamp=$(date -d "$expiryDate" +%s)
        currentTimestamp=$(date +%s)
        daysLeft=$(( (expiryTimestamp - currentTimestamp) / 86400 ))

        profileName=$(basename "$certFile" .crt)
        if [[ "$daysLeft" -lt 0 ]]; then
            echo "🚨 Certificate for profile '$profileName' has EXPIRED on $expiryDate."
        elif [[ "$daysLeft" -le "$days" ]]; then
            echo "⚠️ Certificate for profile '$profileName' expires in $daysLeft days ($expiryDate)."
        fi
    done
}

# Function to list user profiles
listClients() {
    echo "List of client profiles:"
    ls "$outputClientPath"/*.ovpn 2>/dev/null | sed 's/.*\///; s/\.ovpn$//' || echo "No profiles found."
}

# Function to list base configurations
listConfigs() {
    echo "List of base configurations:"
    ls "$baseClientPath" 2>/dev/null || echo "No configurations found."
}

# Function to list servers
listServers() {
    echo "List of servers:"
    ls "$serverConfigPath/$serverConfigPrefix"*.conf 2>/dev/null | sed 's/.*\///; s/\.conf$//' || echo "No servers found."
}

# Function to show connected users
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $*" >&2
}

hr() {
  numfmt --to=iec-i --suffix=B "${1}"
}

# Function to list connected clients
listInfoClients() {
  {
    printf "\e[4mName\e[0m  \t  \e[4mRemote IP\e[0m  \t  \e[4mNet name\e[0m  \t "
    printf "\e[4mVirtual IP\e[0m  \t  \e[4mBytes Received\e[0m  \t  "
    printf "\e[4mBytes Sent\e[0m  \t  \e[4mConnected Since\e[0m\n"

    if grep -q "^CLIENT_LIST" "${STATUS_LOG}"; then
      while read -r line; do
        read -r -a array <<< "${line}"

        [[ "${array[0]}" == 'CLIENT_LIST' ]] || continue

        printf "%s  \t  %s  \t  " "${array[1]}" "${array[2]}"
        IFS=':' read -ra IP <<< "${array[2]}"
        net=$(whois ${IP[0]} | grep -m1 netname | awk '{print $2}')
        printf "%s  \t " "${net:-N/A}"

        printf "%s  \t  " "${array[3]}"

        if [[ "${HR}" == 1 ]]; then
          printf "%s  \t  %s" "$(hr "${array[4]}")" "$(hr "${array[5]}")"
        else
          printf "%'d  \t  %'d" "${array[4]}" "${array[5]}"
        fi
        printf "  \t  %s %s %s " "${array[6]}" "${array[7]}"
        printf "\n"
      done < "${STATUS_LOG}"
    else
      printf "\nNo Clients Connected!\n"
    fi

    printf "\n"
  } | column -t -s $'\t'
}

# Function to show connected users
showInfo() {
    NAMES=()
    LOGS=()
    for conf in "$serverConfigPath/$serverConfigPrefix"*.conf; do
        if [[ -f "$conf" ]]; then
            name=$(basename "$conf" | sed 's/.*\///; s/\.conf$//')
            NAMES+=("$name")
            status_log=$(grep '^status ' "$conf" | awk '{print $2}')
            LOGS+=("$status_log")
        fi
    done
    for i in ${!NAMES[@]}; do
        echo "- - - - -"
        echo "${bold}${NAMES[$i]}${normal}"
        echo "- - - - -"
        STATUS_LOG=${LOGS[$i]}
        if [[ ! -f "${STATUS_LOG}" ]]; then
            echo "Error: The file '${STATUS_LOG}' was not found!"
            exit 1
        fi
        HR=1
        listInfoClients
        echo ""
    done
}

# Function to show login history
showLog() {
    local username="$1"
    echo "Displaying login and disconnection history for user '$username'..."
    echo "... under construction ..."
}

# Function to add a new client profile
addProfile() {
    local profileName="$1"
    local profileBaseConfig="$2"

    if [[ -z "$profileName" ]]; then
        echo "No client profile name provided!"
        exit 1
    fi
    if [[ -z "$profileBaseConfig" ]]; then
        echo "No configuration provided!"
        exit 1
    fi

    local baseClientConfig="$profileBaseConfig"
    if [[ -f "$baseClientPath/$baseClientConfig" ]]; then
        echo "Using client profile config: $baseClientConfig"
    else
        echo "Client profile config does not exist! ($baseClientPath/$baseClientConfig)"
        exit 1
    fi

    if [[ -f "$reqPath/$profileName.req" || -f "$issuedPath/$profileName.crt" || -f "$privatePath/$profileName.key" || -f "$outputClientPath/$profileName.ovpn" ]]; then
        echo "${bold}$profileName${normal} - client exists - skipping. Delete files to add this user:"
        [[ -f "$reqPath/$profileName.req" ]] && echo "   - $reqPath/$profileName.req"
        [[ -f "$issuedPath/$profileName.crt" ]] && echo "   - $issuedPath/$profileName.crt"
        [[ -f "$privatePath/$profileName.key" ]] && echo "   - $privatePath/$profileName.key"
        [[ -f "$outputClientPath/$profileName.ovpn" ]] && echo "   - $outputClientPath/$profileName.ovpn"
        echo " Or use command: $scriptFile remove $profileName"
        exit 1
    else
        cd "$easyRsaPath" || exit
        echo "Generating profile for client ${bold}$profileName${normal}"
        ./easyrsa build-client-full "$profileName" nopass
        cp "$baseClientPath/$baseClientConfig" "$outputClientPath/$profileName.ovpn"

        {
            echo "<ca>"
            cat "$caCertFile"
            echo "</ca>"
            echo "<cert>"
            cat "$issuedPath/$profileName.crt"
            echo "</cert>"
            echo "<key>"
            cat "$privatePath/$profileName.key"
            echo "</key>"
            echo "<tls-crypt>"
            cat "$taKeyFile"
            echo "</tls-crypt>"
        } >> "$outputClientPath/$profileName.ovpn"

        echo ""
        echo "${bold}$profileName${normal} - client added, configuration is available at $outputClientPath/$profileName.ovpn"
        cd - > /dev/null || exit
    fi
}

# Function to remove a client profile
removeProfile() {
    local profileName="$1"

    if [[ -z "$profileName" ]]; then
        echo "No client profile name provided!"
        exit 1
    fi

    if [[ -f "$reqPath/$profileName.req" || -f "$issuedPath/$profileName.crt" || -f "$privatePath/$profileName.key" || -f "$outputClientPath/$profileName.ovpn" ]]; then
        read -rp "Are you sure you want to remove client ${bold}$profileName${normal} (y/n)? " choice
        case "$choice" in
            y|Y )
                local timestamp
                timestamp=$(date +%s)
                local backup="$removedClientPath/$profileName-$timestamp"
                mkdir -p "$backup"

                [[ -f "$reqPath/$profileName.req" ]] && mv -f "$reqPath/$profileName.req" "$backup"
                [[ -f "$issuedPath/$profileName.crt" ]] && mv -f "$issuedPath/$profileName.crt" "$backup"
                [[ -f "$privatePath/$profileName.key" ]] && mv -f "$privatePath/$profileName.key" "$backup"
                [[ -f "$outputClientPath/$profileName.ovpn" ]] && mv -f "$outputClientPath/$profileName.ovpn" "$backup"
                [[ -f "$configClientPath/$profileName" ]] && mv -f "$configClientPath/$profileName" "$backup"

        
                echo "Backup created: $backup"
                echo "Refreshing CRL..."
                cd "$easyRsaPath" || exit
                ./easyrsa gen-crl
                cp "$crlPemFile" "$openvpnCrlFile"
                chmod 644 "$openvpnCrlFile"
                cd - > /dev/null || exit

                echo ""
                echo "${bold}$profileName${normal} - client removed"
            ;;
            * )
                echo "Aborted."
            ;;
        esac
    else
        echo "Nothing to do. Client ${bold}$profileName${normal} does not exist."
    fi
}

# Function to copy client profiles to a user's home directory
copyProfiles() {
    local localUserName="$1"

    if [[ -z "$localUserName" ]]; then
        echo "No local username provided!"
        exit 1
    fi

    if id "$localUserName" &>/dev/null; then
        local userHome
        userHome=$(eval echo ~$localUserName)

        if [[ ! -d "$userHome" ]]; then
            echo "Home directory for local user '$localUserName' does not exist!"
            exit 1
        fi
        local targetDir="$userHome$clientProfilesDir"
        [[ -d "$targetDir" ]] && rm -rf "$targetDir"
        mkdir -p "$targetDir"
        cp -r "$outputClientPath/"* "$targetDir"
        chown -hR "$localUserName" "$targetDir"
        chmod 600 "$targetDir"/*
        chmod 700 "$targetDir"

        echo "All client profiles copied to local user '$localUserName' home directory ($targetDir)"
    else
        echo "Local user '$localUserName' does not exist!"
        exit 1
    fi
}

# Restart OpenVPN service (with all servers)
restartServers() {
    echo "Restarting OpenVPN servers..."
    for file in "$serverConfigPath/$serverConfigPrefix"*.conf; do
        if [[ -f "$file" ]]; then
            filename="$(basename "${file%.conf}")"
            echo "- $filename"
            systemctl restart openvpn-server@$filename
        fi
    done
}

# Command handling
case "$1" in
    add) addProfile "$2" "$3" ;;
    remove) removeProfile "$2" ;;
    copy) copyProfiles "$2" ;;
    info) showInfo ;;
    check) checkCertificates "$2" ;;
    log) showLog "$2" ;;
    restart) restartServers ;;
    list)
        case "$2" in
            profiles) listClients ;;
            configs) listConfigs ;;
            servers) listServers ;;
            *) usage ;;
        esac
        ;;
    update) checkAndUpdateScript ;;
    *) usage ;;
esac
