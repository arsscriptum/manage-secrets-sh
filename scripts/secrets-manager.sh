#!/bin/bash

# =========================================================
# variables:    colors definitions
# description:  used in logging functions
# =========================================================

WHITE='\033[0;97m'
WHITEIT='\033[3;97m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color


# =========================================================
# variables:    flages for script modes
# description:  keep track of execution mode like verbose
# =========================================================

TEST_MODE=0
VERBOSE_MODE=0


# =========================================================
# variables:    global paths 
# description:  path that are resolve at the beginning 
#               of the script, variables used globally
# =========================================================

SCRIPT_PATH=$(realpath "$BASH_SOURCE")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

tmp_root=$(pushd "$SCRIPT_DIR/.." | awk '{print $1}')
ROOT_DIR=$(eval echo "$tmp_root")
ENV_FILE="$ROOT_DIR/.env"
AGE_DIRECTORY="$ROOT_DIR/age"
AGE_PACKAGE="$AGE_DIRECTORY/age.tar.gz"
LOGS_DIR="$ROOT_DIR/logs"
LOG_FILE="$LOGS_DIR/op.log"

ME=`whoami`
MYHOME="/home/$ME"
MYSECRETS="$MYHOME/.secrets"

# =========================================================
# variables:    secret paths
# description:  paths used for encryption keys
# =========================================================

KEYS_PATH="$MYSECRETS/.keys"
KEYS_BACKUP_PATH="$MYSECRETS/.keys_backup"
CREDENTIALS_PATH="$MYSECRETS/credentials"

PRIVATE_KEY="$KEYS_PATH/${ME}-ed25prv.pem"
PUBLIC_KEY="$KEYS_PATH/${ME}-ed25pub.pem"
AES_KEY_CLEAR="$KEYS_PATH/${ME}-aes.key"
AES_KEY_CODED="$KEYS_PATH/${ME}-aes.enc"
AES_KEY_CLEAR_BAK="$KEYS_BACKUP_PATH/${ME}-aes.key"
AES_KEY_CODED_BAK="$KEYS_BACKUP_PATH/${ME}-aes.enc"

# =========================================================
# section:      directory creations
# =========================================================

mkdir -p "$LOGS_DIR"
mkdir -p "$AGE_DIRECTORY"
mkdir -p "$MYSECRETS"
mkdir -p "$KEYS_PATH"
mkdir -p "$KEYS_BACKUP_PATH"
mkdir -p "$CREDENTIALS_PATH"


# =========================================================
# variables:    age related variables
# description:  used in install_age() function
# =========================================================

AGE_VERSION="v1.2.1"
AGE_PLATFORM="linux-amd64"

AGE_URL="https://github.com/FiloSottile/age/releases/download/${AGE_VERSION}/age-${AGE_VERSION}-${AGE_PLATFORM}.tar.gz"
AGE_LOGFILE="/tmp/age-gl.log"

# =========================================================
# function:     logs functions
# description:  log messages to fils and console
#              
# =========================================================

log_ok() {
    echo -e "✅ ${WHITE}$1${NC}"
    echo -e "✅ [$(date +%H:%M:%S)] $1" >> "$LOG_FILE"
}
log_info() {
    echo -e "${CYAN}🛈${NC} ${WHITE}$1${NC}"
    echo -e "${CYAN}🛈${NC} ${WHITE}[$(date +%H:%M:%S)] $1${NC}" >> "$LOG_FILE"
}
log_warn() {
    echo -e "⚠ [$(date +%H:%M:%S)] $1" >> "$LOG_FILE"
    echo -e "⚠ ${YELLOW}$1${NC}"
}
log_error() {
    echo "❌ [$(date +%H:%M:%S)] $1" >> "$LOG_FILE"
    echo -e "❌ ${YELLOW}$1${NC}"
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root"
	exit 1
fi


# =========================================================
# function:     install_age
# description:  install the age app
# =========================================================

install_age() {
	if [[ -f "$AGE_PACKAGE" ]]; then
	   log_info "package already on disk \"$AGE_PACKAGE\""
	   return 0
	fi

	log_info "[install_age] Installing age ($AGE_PLATFORM) version ${AGE_VERSION}"
	log_info "[install_age] go in $AGE_DIRECTORY"
	pushd "$AGE_DIRECTORY" > /dev/null

	if which wget > /dev/null 2>&1; then
	   log_info "[install_age] download age package ${AGE_VERSION} using wget to $AGE_PACKAGE..."
	   wget --output-file="$AGE_LOGFILE" --max-redirect 2 --no-cache --connect-timeout=5  --waitretry=3 --tries=3 --output-document="$AGE_PACKAGE" "$AGE_URL" > "$AGE_LOGFILE" 2>&1
	else 
		log_info "[install_age] download age package ${AGE_VERSION} using curl to $AGE_PACKAGE..."
	   	curl -vL "$AGE_URL" -o "$AGE_PACKAGE" > "$AGE_LOGFILE" 2>&1
	fi


	if [[ ! -e "$AGE_PACKAGE" ]]; then
	   log_error "problem when downloading package."
	   return 1
	fi

	INSTALL_PATH="/usr/local/bin/"
	if [[ $TEST_MODE -eq 1 ]]; then	
		INSTALL_PATH="$MYHOME/test_install_age"
		mkdir -p "$INSTALL_PATH"
		log_info "[install_age] test mode enabled"
	fi

	if [[ $VERBOSE_MODE -eq 1 ]]; then	
		VERBOSE_OPTION="-v"
	else
		VERBOSE_OPTION=""
	fi

	EXTRACTED_PATH="$AGE_DIRECTORY/extracted"
	mkdir -p "$EXTRACTED_PATH"

	log_info "[install_age] extracting to $EXTRACTED_PATH"
	log_info "[install_age] installing to $INSTALL_PATH"

	tar -xzvf "$AGE_PACKAGE" -C "$EXTRACTED_PATH"

	log_info "[install_age] installing age"
	sudo mv $VERBOSE_OPTION "$EXTRACTED_PATH/age/age" "$INSTALL_PATH"
	log_info "[install_age] installing age-keygen"
	sudo mv $VERBOSE_OPTION "$EXTRACTED_PATH/age/age-keygen" "$INSTALL_PATH"
	log_info "[install_age] setting permissions"
	sudo chmod +x "$INSTALL_PATH/age" "$INSTALL_PATH/age-keygen" $VERBOSE_OPTION

	log_info "[install_age] cleaning up..."
	rm -rf "$EXTRACTED_PATH" "$AGE_PACKAGE" $VERBOSE_OPTION

	log_info "[install_age] testing..."
	AGEVER=$(age --version 2> /dev/null)
	if [[ $? -eq 0 ]]; then
		AGELOC=$(which age)
		log_ok "age installed successfully! $AGELOC ($AGEVER)"
	else
		log_error "error while installing age ($?)"
		return 1
	fi

	popd  > /dev/null

	return 0
}

validate_age_app() {

	AGEVER=$(age --version 2> /dev/null)
	if [[ $? -eq 0 ]]; then
		return 0
	fi

	return 1
}

validate_ed25519_key_pair() {
	if [[ -f "$PRIVATE_KEY" && -f "$PUBLIC_KEY" ]]; then
		log_ok "detected ed25519 key pair"
		return 0	
	fi 

	log_warning "missing ed25519 keys"
	return 1
}

validate_apps() {

	OPENSSL_VERSION=$(openssl version 2> /dev/null)
	if [[ $? -eq 0 ]]; then
		log_ok "openssl detected $OPENSSL_VERSION"
	else
		log_error "missing openssl: please install \"openssl\" to continue."
		return 1
	fi

	AESCRYPT_VERSION=$(aescrypt -v 2> /dev/null | head -n  1 | awk  '{ print $2 }')
	if [[ $? -eq 0 ]]; then
		log_ok "aescrypt detected $AESCRYPT_VERSION"
	else
		log_error "missing openssl: please install \"openssl\" to continue."
		return 1
	fi

	return 0
}

# =========================================================
# variables:    colors definitions
# description:  used in logging functions
# =========================================================

init_crypto(){
	
	log_info "Generate Ed25519 Key Pair"
	openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY"

	log_info "Extract the public key from the private key: \"$PRIVATE_KEY\""
	openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
	log_ok "key extracted: $PUBLIC_KEY"

	log_info "Generate a random symmetric key (AES)."
	aescrypt -g -k "$AES_KEY_CLEAR"
	log_ok "key generated: $AES_KEY_CLEAR"

	# Since OpenSSL does not support Ed25519 encryption, we use X25519 (related to Ed25519 but for encryption):
	# openssl pkeyutl -encrypt -pubin -inkey "$PUBLIC_KEY" -in "$AES_KEY_CLEAR" -out "$AES_KEY_CODED"
}

encrypt_key(){
	if [[ ! -f "$AES_KEY_CLEAR" ]]; then
		log_error "missing aes key [$AES_KEY_CLEAR]"
		return 1
	fi 

	if [[ -f "$AES_KEY_CODED" ]]; then
		log_warning "coded aes key is present, remove"
		rm -rf "$AES_KEY_CODED"
	fi 
	
	age -R "$PRIVATE_KEY" -o "$AES_KEY_CODED" "$AES_KEY_CLEAR"
	if [[ $? -eq 0 ]]; then
		log_ok "aeskey encrypted $AES_KEY_CODED"
	else
		log_error "error on aeskey cipher [$AES_KEY_CLEAR]"
		return 1
	fi 

	log_warning "backup clear key to $AES_KEY_CLEAR_BAK"
	cp -f "$AES_KEY_CLEAR" "$AES_KEY_CLEAR_BAK"

	log_warning "cleaning up aes key"
	rm -rf "$AES_KEY_CLEAR"

	return 0
}

decrypt_key(){
	if [[ ! -f "$AES_KEY_CODED" ]]; then
		log_error "missing coded aes key [$AES_KEY_CODED]"
		return 1
	fi 

	if [[ -f "$AES_KEY_CLEAR" ]]; then
		log_warning "decrypted aes key is present, remove"
		mv "$AES_KEY_CLEAR" "$KEYS_BACKUP_PATH/clear.aes"
	fi 
	
	log_info "Decrypt the AES key using the private key"
	age -d -i "$PRIVATE_KEY" -o "$AES_KEY_CLEAR" "$AES_KEY_CODED"
	if [[ $? -eq 0 ]]; then
		log_ok "aeskey encrypted $AES_KEY_CODED"
	else
		log_error "error on aeskey cipher [$AES_KEY_CLEAR]"
		return 1
	fi 

	log_warning "cleaning up coded aes key"
	rm -rf "$AES_KEY_CODED"

	return 0
}


if ! validate_age_app; then
	if install_age; then
		log_info "installed age!"
	else 
		log_error "problem while installing age"
		exit 1
	fi
fi

if ! validate_apps; then
	log_error "problem: missing dependency"
	exit 1
fi


log_info "test validate_ed25519_key_pair"
if ! validate_ed25519_key_pair; then
	log_warning "failed:  init_crypto"
	init_crypto
fi


log_info "test encrypt_key"
encrypt_key

log_info "test decrypt_key"
decrypt_key
	
