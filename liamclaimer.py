import time
import requests
import os
from datetime import datetime, timedelta, timezone
from colorama import init, Fore
import warnings
import re
import itertools
import concurrent.futures

# Suppress only the specific DeprecationWarning
warnings.filterwarnings("ignore", category=DeprecationWarning)

init(autoreset=True)

# URLs for Microsoft OAuth2 and Minecraft API
LOGIN_URL = "https://login.live.com/oauth20_authorize.srf"
XBOX_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MINECRAFT_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
MOJANG_USERNAME_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/name/{username}"
MINECRAFT_PROFILE_POST_URL = "https://api.minecraftservices.com/minecraft/profile"
MINECRAFT_SKIN_CHANGE_URL = "https://api.minecraftservices.com/minecraft/profile/skins"
MINECRAFT_NAME_CHECK_URL = "https://api.minecraftservices.com/minecraft/profile"

# Re-authentication interval
REAUTH_INTERVAL = 86400  # Re-authentication interval (24 hours)

# Hardcoded skin URL for skin change
SKIN_URL = "file:///C:/Users/liamn/Downloads/rsz_8bb8c567f32488de.png"


# Function to generate file paths if they don't exist
def setup_files():
    os.makedirs('files', exist_ok=True)

    if not os.path.exists('files/accounts.txt'):
        print(Fore.RED + "No accounts file found. Generating default 'accounts.txt' file.")
        with open('files/accounts.txt', 'w') as f:
            f.write("email:pass\n")  # Creating a template line

    if not os.path.exists('files/proxies.txt'):
        print(Fore.RED + "No proxies file found. Generating default 'proxies.txt' file.")
        with open('files/proxies.txt', 'w') as f:
            f.write("# Add your proxies here (format: IP:PORT or IP:PORT:username:password)\n")


# Proxy handling
def load_proxies():
    proxies = []
    if os.path.exists('files/proxies.txt'):
        with open('files/proxies.txt', 'r') as file:
            proxies = [line.strip() for line in file if line.strip() and not line.startswith("#")]
    return proxies


def get_proxy(proxies):
    if proxies and len(proxies) > 0:
        proxy = proxies.pop(0)
        proxies.append(proxy)  # Rotate proxy

        # Detect SOCKS5 proxies by checking if they start with "socks5://"
        if proxy.startswith('socks5://'):
            return {
                "http": proxy,
                "https": proxy
            }
        else:
            return {
                "http": f"http://{proxy}",
                "https": f"https://{proxy}"
            }
    return None  # No proxy will be used


# Step 1: Extract login data (sFTTag and urlPost)
def extract_sfttag_and_urlpost(session, proxies=None):
    proxy = get_proxy(proxies)
    response = session.get(
        f"{LOGIN_URL}?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en",
        allow_redirects=True,
        proxies=proxy
    )

    if response.status_code != 200:
        raise Exception(f"Failed to load login page for account: {response.status_code}")

    ppft_match = re.search(r'value="(.+?)"', response.text)
    urlpost_match = re.search(r"urlPost:'(.+?)'", response.text)

    if ppft_match:
        sfttag = ppft_match.group(1)
    else:
        raise ValueError("Could not find the sFTTag (PPFT value) on the page")

    if urlpost_match:
        urlpost = urlpost_match.group(1)
    else:
        raise ValueError("Could not find the urlPost value on the page")

    return sfttag, urlpost


# Step 2: Microsoft login with email and password
def microsoft_login(session, email, password, sfttag, urlpost, proxies=None):
    payload = {
        'login': email,
        'loginfmt': email,
        'passwd': password,
        'PPFT': sfttag
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    proxy = get_proxy(proxies)
    response = session.post(urlpost, data=payload, headers=headers, allow_redirects=True, proxies=proxy)
    if "accessToken" in response.url:
        return True
    elif "Sign in to" in response.text:
        return None  # Failed login, return None to move to next account
    elif "Help us protect your account" in response.text:
        raise Exception(f"2FA enabled for {email}, remove it to proceed.")
    return response.url


# Step 3: Extract token from the URL after successful login
def extract_token_from_url(url):
    if url is None:
        return None
    token_data = dict(param.split('=') for param in url.split('#')[1].split('&'))
    return token_data.get('access_token')


# Step 4: Authenticate with Xbox Live and get XSTS token
def authenticate_xbox_live(session, access_token, proxies=None):
    xbox_auth_payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": access_token
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-xbl-contract-version": "1"
    }
    proxy = get_proxy(proxies)
    response = session.post(XBOX_AUTH_URL, json=xbox_auth_payload, headers=headers, proxies=proxy)
    if response.status_code == 200:
        xbox_token = response.json()
        return xbox_token['Token'], xbox_token['DisplayClaims']['xui'][0]['uhs']
    else:
        return None, None


# Step 5: Get XSTS token for Minecraft
def get_xsts_token(session, xbox_token, uhs, proxies=None):
    if not xbox_token or not uhs:
        return None
    xsts_payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbox_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    proxy = get_proxy(proxies)
    response = session.post(XSTS_AUTH_URL, json=xsts_payload, headers=headers, proxies=proxy)
    if response.status_code == 200:
        xsts_token = response.json()['Token']
        return xsts_token
    else:
        return None


# Step 6: Authenticate to Minecraft using XSTS token
def authenticate_minecraft(session, email, xsts_token, uhs, proxies=None):
    if not xsts_token:
        return None
    minecraft_payload = {
        "identityToken": f"XBL3.0 x={uhs};{xsts_token}"
    }
    headers = {"Content-Type": "application/json"}
    proxy = get_proxy(proxies)
    response = session.post(MINECRAFT_LOGIN_URL, json=minecraft_payload, headers=headers, proxies=proxy)
    if response.status_code == 200:
        minecraft_token = response.json()
        print(Fore.GREEN + f"Successfully authenticated {email}")
        return minecraft_token['access_token']
    else:
        print(Fore.RED + f"Failed to authenticate {email}")
        return None


# Function to check if the account has a name or not
def check_account_name_status(access_token, proxies=None):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    url = "https://api.minecraftservices.com/minecraft/profile"
    proxy = get_proxy(proxies)

    try:
        response = requests.get(url, headers=headers, proxies=proxy)
        if response.status_code == 200:
            # If the profile is found, the account has a name
            return True  # Account has a Minecraft name
        elif response.status_code == 404:
            # 404 means the account does not have a profile (i.e., no Minecraft name)
            return False  # Account does not have a name
        else:
            return True  # Default to True (named) if there's an unknown issue
    except Exception as e:
        print(f"Error checking account name: {e}")
        return True  # Default to True (named) if there's an error


# Function to check multiple accounts in parallel using threading
def check_all_account_names(authenticated_accounts, proxies=None):
    account_name_statuses = {}  # To store whether each account is named or not

    # Use a ThreadPoolExecutor to run the checks in parallel
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Map each account's access_token to the check_account_name_status function
        future_to_account = {
            executor.submit(check_account_name_status, access_token, proxies): email
            for email, access_token in authenticated_accounts
        }

        for future in concurrent.futures.as_completed(future_to_account):
            email = future_to_account[future]
            try:
                is_named = future.result()  # Get the result from the future (True if named, False if non-named)
                account_name_statuses[email] = is_named
            except Exception as e:
                account_name_statuses[email] = True  # Default to True (named) if there's an issue

    return account_name_statuses


# Function to change Minecraft skin using the hardcoded skin URL
def change_minecraft_skin(access_token, proxies=None):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    change_skin_url = MINECRAFT_SKIN_CHANGE_URL

    payload = {
        "variant": "classic",  # Change to "slim" if needed
        "url": SKIN_URL
    }

    proxy = get_proxy(proxies)
    response = requests.post(change_skin_url, headers=headers, json=payload, proxies=proxy)

    if response.status_code == 204:
        print(Fore.GREEN + "Skin changed successfully.")
    else:
        print(Fore.RED + f"Failed to change skin. Status Code: {response.status_code}")


# Function to handle name change requests for named accounts (PUT request)
def change_minecraft_username_named(email, access_token, target_username, proxies=None, named_delay=10):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    change_url = MOJANG_USERNAME_CHANGE_URL.format(username=target_username)
    proxy = get_proxy(proxies)

    response = requests.put(change_url, headers=headers, proxies=proxy)

    try:
        response_json = response.json()  # Parse the response JSON
        status = response_json.get('details', {}).get('status', 'NONE')
    except (ValueError, KeyError):  # Handle potential issues with missing or malformed JSON
        status = "NONE"

    if response.status_code == 200:
        print(Fore.GREEN + f"[{target_username}] 200, Successfully claimed on {email} | {datetime.now()}")
        change_minecraft_skin(access_token, proxies=None)
        return True, 200  # Return success and status code

    elif response.status_code == 429:  # Too Many Requests
        print(Fore.RED + f"[{target_username}] 429 | TOO_MANY_REQUESTS | {datetime.now()}")
        return False, 429  # Return failure and status code

    elif response.status_code == 401:  # Unauthorized
        print(Fore.RED + f"[{target_username}] 401 | UNAUTHORIZED | {datetime.now()}")
        return False, 401  # Return failure and status code

    else:
        print(Fore.LIGHTCYAN_EX + f"[{target_username}] {response.status_code} | {status} | {datetime.now()}")
        return False, response.status_code  # Return failure and the status code


# Function to handle name registration for non-named accounts (POST request)
def change_minecraft_username_non_named(email, access_token, target_username, proxies=None, non_named_delay=15):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    change_url = "https://api.minecraftservices.com/minecraft/profile"  # POST for non-named accounts
    proxy = get_proxy(proxies)

    payload = {
        "profileName": target_username
    }

    response = requests.post(change_url, headers=headers, json=payload, proxies=proxy)

    try:
        response_json = response.json()  # Parse the response JSON
        status = response_json.get('details', {}).get('status', 'NONE')
    except (ValueError, KeyError):  # Handle potential issues with missing or malformed JSON
        status = "NONE"

    if response.status_code == 200:
        print(Fore.GREEN + f"[{target_username}] 200, Successfully claimed on {email} | {datetime.now()}")
        change_minecraft_skin(access_token, proxies=None)
        return True, 200  # Return success and status code

    elif response.status_code == 429:  # Too Many Requests
        print(Fore.RED + f"[{target_username}] 429 | TOO_MANY_REQUESTS | {datetime.now()}")
        return False, 429  # Return failure and status code

    elif response.status_code == 401:  # Unauthorized
        print(Fore.RED + f"[{target_username}] 401 | UNAUTHORIZED | {datetime.now()}")
        return False, 401  # Return failure and status code

    else:
        print(Fore.LIGHTCYAN_EX + f"[{target_username}] {response.status_code} | {status} | {datetime.now()}")
        return False, response.status_code  # Return failure and the status code


# Function to load accounts from the file
def load_accounts():
    accounts = []
    if os.path.exists('files/accounts.txt'):
        with open('files/accounts.txt', 'r') as file:
            for line in file.readlines():
                if ':' in line:
                    email, password = line.strip().split(':')
                    accounts.append((email, password))
    return accounts


# Function to handle round-robin requests for both named and non-named accounts
def round_robin_requests(authenticated_accounts, target_username, proxies):
    cycle_accounts = itertools.cycle(authenticated_accounts)
    num_accounts = len(authenticated_accounts)

    # Check whether each account is named or non-named before starting requests
    account_name_statuses = check_all_account_names(authenticated_accounts, proxies)

    # Base delays for named and non-named accounts
    named_account_base_delay = 10
    non_named_account_base_delay = 15

    # Create a delay map for each account based on whether they are named or non-named
    delay_map = {
        email: named_account_base_delay if account_name_statuses[email] else non_named_account_base_delay
        for email, _ in authenticated_accounts
    }

    # Calculate proportional delays based on the number of accounts
    for email in delay_map:
        delay_map[email] = delay_map[email] / num_accounts

    while True:
        email, access_token = next(cycle_accounts)

        # Determine if the account is named or non-named based on the status check
        if account_name_statuses[email]:
            success, response_code = change_minecraft_username_named(email, access_token, target_username, proxies)
        else:
            success, response_code = change_minecraft_username_non_named(email, access_token, target_username, proxies)

        # Apply the proportional delay for the current account
        delay = delay_map[email]

        if response_code == 429:
            time.sleep(delay)
            continue  # Continue with the loop to retry with delay applied

        # Apply the proportional delay for the current account after successful or failed requests
        time.sleep(delay)

        # Break the loop if the request was successful (status code 200)
        if success:
            break


# Re-authentication process every 24 hours
def reauthenticate_accounts(accounts, proxies):
    print(Fore.CYAN + "Re-authing all accounts...")

    authenticated_accounts = []
    for email, password in accounts:
        with requests.Session() as session:
            try:
                sfttag, urlpost = extract_sfttag_and_urlpost(session, proxies)
                login_url = microsoft_login(session, email, password, sfttag, urlpost, proxies)
                access_token = extract_token_from_url(login_url)
                if access_token:
                    xbox_token, uhs = authenticate_xbox_live(session, access_token, proxies)
                    xsts_token = get_xsts_token(session, xbox_token, uhs, proxies)
                    minecraft_token = authenticate_minecraft(session, email, xsts_token, uhs, proxies)
                    if minecraft_token:
                        authenticated_accounts.append((email, minecraft_token))
                        print(Fore.GREEN + f"Successfully authenticated {email}")
                else:
                    print(Fore.RED + f"Failed to authenticate {email}")
            except Exception as e:
                print(Fore.RED + f"Error with account {email}: {e}")

    return authenticated_accounts


# Function to update countdown and clear previous message
def update_countdown(message, end_time):
    while datetime.now(timezone.utc) < end_time:
        time_left = end_time - datetime.now(timezone.utc)
        seconds_left = int(time_left.total_seconds())
        print(f'\r{message}: {seconds_left} seconds remaining', end='', flush=True)
        time.sleep(1)
    print('')  # Clears the line after the countdown ends


def start_authentication_and_snipe(accounts, drop_time, target_username, proxies=None):
    authenticated_accounts = []
    current_time = datetime.now(timezone.utc)  # Ensure timezone-aware datetime

    # Always show countdown or start message regardless of drop_time being None (i.e., 'ignore')
    if drop_time is not None:
        # Start authentication 8 hours before the first UNIX drop range
        auth_start_time = drop_time - timedelta(hours=8)

        # Wait until authentication starts and update every second
        while current_time < auth_start_time:
            time_until_auth = (auth_start_time - current_time).total_seconds()
            print(Fore.CYAN + f"\rAuthing in {int(time_until_auth)} seconds...", end="", flush=True)
            time.sleep(1)
            current_time = datetime.now(timezone.utc)  # Update current time each second

    print(Fore.CYAN + "Starting auth...")  # This prints when authentication starts

    for email, password in accounts:
        with requests.Session() as session:
            try:
                sfttag, urlpost = extract_sfttag_and_urlpost(session, proxies)
                login_url = microsoft_login(session, email, password, sfttag, urlpost, proxies)
                access_token = extract_token_from_url(login_url)
                if access_token:
                    xbox_token, uhs = authenticate_xbox_live(session, access_token, proxies)
                    xsts_token = get_xsts_token(session, xbox_token, uhs, proxies)
                    minecraft_token = authenticate_minecraft(session, email, xsts_token, uhs, proxies)
                    if minecraft_token:
                        authenticated_accounts.append((email, minecraft_token))
                else:
                    print(Fore.RED + f"Skipping {email} due to failed authentication.")
            except Exception as e:
                print(Fore.RED + f"Error with account {email}: {e}")

    # Now print the authentication success message immediately after the authentication process
    if len(authenticated_accounts) > 0:
        print(Fore.GREEN + f"Successfully authenticated {len(authenticated_accounts)} accounts.")
    else:
        print(Fore.RED + "No accounts were successfully authenticated. Exiting...")
        return  # Exit if no accounts are authenticated

    # Proceed with sniping, even if drop_time is None (i.e., 'ignore')
    if drop_time is None:
        # Drop time was set to 'ignore', so we start sniping immediately

        # Then show the snipe start message
        print(Fore.MAGENTA + f"Starting snipe using {len(authenticated_accounts)} accounts, {len(proxies)} proxies...")

    else:
        # Wait until 5 seconds before the UNIX drop range to start sniping
        snipe_start_time = drop_time - timedelta(seconds=5)
        current_time = datetime.now(timezone.utc)

        # Show countdown every second until sniping starts
        while current_time < snipe_start_time:
            time_until_snipe = (snipe_start_time - current_time).total_seconds()
            print(Fore.CYAN + f"\rSniping {target_username} in {int(time_until_snipe)} seconds...", end="", flush=True)
            time.sleep(1)
            current_time = datetime.now(timezone.utc)  # Update current time each second

        # Clear the countdown message line by printing a blank line
        print("\r" + " " * 80, end="\r", flush=True)

        # Then show the snipe start message
        print(Fore.MAGENTA + f"Starting snipe using {len(authenticated_accounts)} accounts, {len(proxies)} proxies...")

    round_robin_requests(authenticated_accounts, target_username, proxies)

    while True:
        time.sleep(REAUTH_INTERVAL)
        authenticated_accounts = reauthenticate_accounts(accounts, proxies)
        round_robin_requests(authenticated_accounts, target_username, proxies)

# Main entry point for the script
if __name__ == "__main__":
    setup_files()
    accounts = load_accounts()

    if len(accounts) == 0:
        print(Fore.RED + "No accounts loaded. Please add accounts to 'accounts.txt' to proceed.")
        exit(1)

    target_username = input(Fore.BLUE + "Target Username: " + Fore.RESET)
    unix_droptime = input(Fore.BLUE + "Drop Range (unixtime1-unixtime2) or type 'ignore' to bypass: " + Fore.RESET)
    proxies = load_proxies()

    try:
        if unix_droptime.strip().lower() == 'ignore':
            drop_time = None
        else:
            drop_time = datetime.utcfromtimestamp(int(unix_droptime.split('-')[0])).replace(tzinfo=timezone.utc)

        start_authentication_and_snipe(accounts, drop_time, target_username, proxies)
    except ValueError as e:
        print(Fore.RED + f"Error: {e}")