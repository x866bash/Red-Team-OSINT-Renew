<<<<<<< HEAD
import requests
from bs4 import BeautifulSoup
import whois
import shodan
from twython import Twython
import json
import socket

# Set your API keys here
SHODAN_API_KEY = 'your_shodan_api_key'
TWITTER_API_KEY = 'your_twitter_api_key'
TWITTER_API_SECRET_KEY = 'your_twitter_api_secret_key'
TWITTER_ACCESS_TOKEN = 'your_twitter_access_token'
TWITTER_ACCESS_SECRET = 'your_twitter_access_secret'
HUNTER_API_KEY = 'your_hunter_api_key'  # For email harvesting
SECURITYTRAILS_API_KEY = 'your_securitytrails_api_key'
CERTSPOTTER_API_KEY = 'your_certspotter_api_key'
ZOOMEYE_API_KEY = 'your_zoomeye_api_key'
CRIMINAL_IP_API_KEY = 'your_criminal_ip_api_key'
CENSYS_API_ID = 'your_censys_api_id'
CENSYS_API_SECRET = 'your_censys_api_secret'
ABUSEIPDB_API_KEY = 'your_abuseipdb_api_key'

# Initialize Shodan and Twitter API clients
shodan_api = shodan.Shodan(SHODAN_API_KEY)
twitter_api = Twython(TWITTER_API_KEY, TWITTER_API_SECRET_KEY, TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET)

def get_domain_info(domain):
    print(f"Gathering WHOIS information for {domain}...")
    domain_info = whois.whois(domain)
    return domain_info

def get_dns_records(domain):
    print(f"Gathering DNS records for {domain}...")
    dns_url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    response = requests.get(dns_url)
    return response.text

def get_social_media_profiles(domain):
    social_media_profiles = {}
    
    print(f"Gathering LinkedIn profiles for {domain}...")
    linkedin_search_url = f"https://www.google.com/search?q=site:linkedin.com+%22{domain}%22"
    response = requests.get(linkedin_search_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    social_media_profiles['LinkedIn'] = [link['href'] for link in soup.find_all('a', href=True) if 'linkedin.com/in/' in link['href']]
    
    print(f"Gathering Twitter profiles for {domain}...")
    twitter_search = twitter_api.search_users(q=domain)
    social_media_profiles['Twitter'] = [user['screen_name'] for user in twitter_search]
    
    return social_media_profiles

def get_shodan_info(domain):
    print(f"Gathering Shodan information for {domain}...")
    dns_lookup = shodan_api.dns.resolve(domain)
    ip_addresses = dns_lookup['matches'][0]['ips']
    
    shodan_info = []
    for ip in ip_addresses:
        host = shodan_api.host(ip)
        shodan_info.append(host)
    
    return shodan_info

def get_reverse_ip_lookup(ip):
    print(f"Performing reverse IP lookup for {ip}...")
    reverse_ip_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    response = requests.get(reverse_ip_url)
    return response.text

def get_breached_data(domain):
    print(f"Checking for breached data related to {domain}...")
    breach_url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{domain}"
    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(breach_url, headers=headers)
    return response.json() if response.status_code == 200 else "No breaches found."

def get_emails(domain):
    print(f"Harvesting email addresses for {domain}...")
    hunter_url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}"
    response = requests.get(hunter_url)
    return response.json() if response.status_code == 200 else "No emails found."

def get_pastebin_mentions(domain):
    print(f"Searching for Pastebin mentions for {domain}...")
    pastebin_url = f"https://www.google.com/search?q=site:pastebin.com+%22{domain}%22"
    response = requests.get(pastebin_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    pastebin_mentions = [link['href'] for link in soup.find_all('a', href=True) if 'pastebin.com' in link['href']]
    return pastebin_mentions

def get_securitytrails_info(domain):
    print(f"Gathering SecurityTrails information for {domain}...")
    url = f"https://api.securitytrails.com/v1/domain/{domain}"
    headers = {'APIKEY': SECURITYTRAILS_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else "No data found."

def get_publicwww_results(domain):
    print(f"Searching PublicWWW for {domain}...")
    publicwww_url = f"https://publicwww.com/websites/%22{domain}%22/"
    response = requests.get(publicwww_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    results = [link['href'] for link in soup.find_all('a', href=True) if domain in link['href']]
    return results

def get_certspotter_info(domain):
    print(f"Gathering CertSpotter information for {domain}...")
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    headers = {'Authorization': f"Bearer {CERTSPOTTER_API_KEY}"}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else "No certificates found."

def get_github_repositories(domain):
    print(f"Searching GitHub for repositories mentioning {domain}...")
    github_url = f"https://api.github.com/search/repositories?q={domain}"
    response = requests.get(github_url)
    return response.json() if response.status_code == 200 else "No repositories found."

def get_wayback_machine_snapshots(domain):
    print(f"Gathering Wayback Machine snapshots for {domain}...")
    url = f"http://archive.org/wayback/available?url={domain}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else "No snapshots found."

def get_zoomeye_info(domain):
    print(f"Gathering ZoomEye information for {domain}...")
    url = f"https://api.zoomeye.org/domain/search?query={domain}"
    headers = {'API-KEY': ZOOMEYE_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else "No data found."

def get_criminal_ip_info(domain):
    print(f"Gathering Criminal-IP information for {domain}...")
    url = f"https://api.criminalip.io/v1/domain/{domain}"
    headers = {'x-api-key': CRIMINAL_IP_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else "No data found."

def get_censys_info(domain):
    print(f"Gathering Censys information for {domain}...")
    url = f"https://censys.io/api/v1/search/ipv4"
    data = {
        'query': domain,
        'fields': ['ip', 'protocols', 'location', 'updated_at']
    }
    response = requests.post(url, auth=(CENSYS_API_ID, CENSYS_API_SECRET), json=data)
    return response.json() if response.status_code == 200 else "No data found."

def get_crtsh_info(domain):
    print(f"Gathering crt.sh information for {domain}...")
    url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else "No certificates found."

def get_abuseipdb_info(ip):
    print(f"Checking AbuseIPDB information for {ip}...")
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers, params=params)
    return response.json() if response.status_code == 200 else "No data found."

def validate_ip_availability(ip):
    print(f"Validating IP availability for {ip}...")
    try:
        socket.gethostbyname(ip)
        return True
    except socket.error:
        return False

def perform_osint(domain):
    osint_report = {}

    osint_report['WHOIS'] = get_domain_info(domain)
    osint_report['DNS'] = get_dns_records(domain)
    osint_report['Social Media'] = get_social_media_profiles(domain)
    osint_report['Shodan'] = get_shodan_info(domain)
    
    # Perform reverse IP lookup on each IP address found
    dns_lookup = shodan_api.dns.resolve(domain)
    ip_addresses = dns_lookup['matches'][0]['ips']
    osint_report['Reverse IP'] = {}
    for ip in ip_addresses:
        osint_report['Reverse IP'][ip] = get_reverse_ip_lookup(ip)
    
    osint_report['Breached Data'] = get_breached_data(domain)
    osint_report['Emails'] = get_emails(domain)
    osint_report['Pastebin Mentions'] = get_pastebin_mentions(domain)
    osint_report['SecurityTrails'] = get_securitytrails_info(domain)
    osint_report['PublicWWW'] = get_publicwww_results(domain)
    osint_report['CertSpotter'] = get_certspotter_info(domain)
    osint_report['GitHub'] = get_github_repositories(domain)
    osint_report['Wayback Machine'] = get_wayback_machine_snapshots(domain)
    osint_report['ZoomEye'] = get_zoomeye_info(domain)
    osint_report['Criminal-IP'] = get_criminal_ip_info(domain)
    osint_report['Censys'] = get_censys_info(domain)
    osint_report['crt.sh'] = get_crtsh_info(domain)
    
    # Validate IP availability and check AbuseIPDB for each IP
    osint_report['IP Validation'] = {}
    osint_report['AbuseIPDB'] = {}
    for ip in ip_addresses:
        ip_valid = validate_ip_availability(ip)
        osint_report['IP Validation'][ip] = ip_valid
        if ip_valid:
            osint_report['AbuseIPDB'][ip] = get_abuseipdb_info(ip)

    with open(f'osint_report_{domain}.json', 'w') as f:
        json.dump(osint_report, f, indent=4)
    
    print(f"OSINT report saved to osint_report_{domain}.json")

if __name__ == '__main__':
    target_domain = input("Enter the target domain: ")
    perform_osint(target_domain)
=======
import os
import json
import socket
import requests
from bs4 import BeautifulSoup
import whois
from dotenv import load_dotenv
from datetime import datetime

# ------------------- Load .env -------------------
load_dotenv()

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
TWITTER_API_KEY = os.getenv('TWITTER_API_KEY', '')
TWITTER_API_SECRET_KEY = os.getenv('TWITTER_API_SECRET_KEY', '')
TWITTER_ACCESS_TOKEN = os.getenv('TWITTER_ACCESS_TOKEN', '')
TWITTER_ACCESS_SECRET = os.getenv('TWITTER_ACCESS_SECRET', '')
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', '')
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', '')
CERTSPOTTER_API_KEY = os.getenv('CERTSPOTTER_API_KEY', '')
ZOOMEYE_API_KEY = os.getenv('ZOOMEYE_API_KEY', '')
CRIMINAL_IP_API_KEY = os.getenv('CRIMINAL_IP_API_KEY', '')
CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

# ------------------- Initialize optional clients -------------------
shodan_api = None
if SHODAN_API_KEY:
    import shodan
    shodan_api = shodan.Shodan(SHODAN_API_KEY)

twitter_api = None
if TWITTER_API_KEY:
    from twython import Twython
    twitter_api = Twython(TWITTER_API_KEY, TWITTER_API_SECRET_KEY,
                          TWITTER_ACCESS_TOKEN, TWITTER_ACCESS_SECRET)

# ------------------- Helper Functions -------------------
def serialize_data(obj):
    """Recursively convert datetime to string for JSON serialization"""
    if isinstance(obj, dict):
        return {k: serialize_data(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_data(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj

def get_domain_info(domain):
    try:
        print(f"[+] WHOIS for {domain}")
        return whois.whois(domain)
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

def get_dns_records(domain):
    try:
        print(f"[+] DNS lookup for {domain}")
        return requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}").text
    except:
        return "DNS lookup failed."

def get_social_media_profiles(domain):
    profiles = {}
    try:
        print(f"[+] LinkedIn profiles for {domain}")
        url = f"https://www.google.com/search?q=site:linkedin.com+%22{domain}%22"
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        profiles['LinkedIn'] = [a['href'] for a in soup.find_all('a', href=True) if 'linkedin.com/in/' in a['href']]
    except:
        profiles['LinkedIn'] = "Failed"
    if twitter_api:
        try:
            print(f"[+] Twitter profiles for {domain}")
            search = twitter_api.search_users(q=domain)
            profiles['Twitter'] = [u['screen_name'] for u in search]
        except:
            profiles['Twitter'] = "Failed"
    else:
        profiles['Twitter'] = "API key not set"
    return profiles

def get_shodan_info(domain):
    if not shodan_api:
        return "Shodan API key not set"
    try:
        print(f"[+] Shodan info for {domain}")
        dns_lookup = shodan_api.dns.resolve(domain)
        ip_list = dns_lookup.get('matches', [{}])[0].get('ips', [])
        return [shodan_api.host(ip) for ip in ip_list]
    except:
        return "Shodan lookup failed"

def get_reverse_ip_lookup(ip):
    try:
        print(f"[+] Reverse IP lookup for {ip}")
        return requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}").text
    except:
        return "Failed"

def get_breached_data(domain):
    try:
        print(f"[+] Checking breaches for {domain}")
        url = f"https://haveibeenpwned.com/api/v2/breachedaccount/{domain}"
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        return r.json() if r.status_code == 200 else "No breaches found"
    except:
        return "Failed"

def get_emails(domain):
    if not HUNTER_API_KEY:
        return "Hunter API key not set"
    try:
        print(f"[+] Harvesting emails for {domain}")
        r = requests.get(f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={HUNTER_API_KEY}")
        return r.json()
    except:
        return "Failed"

def get_pastebin_mentions(domain):
    try:
        print(f"[+] Pastebin mentions for {domain}")
        url = f"https://www.google.com/search?q=site:pastebin.com+%22{domain}%22"
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        return [a['href'] for a in soup.find_all('a', href=True) if 'pastebin.com' in a['href']]
    except:
        return "Failed"

def get_securitytrails_info(domain):
    if not SECURITYTRAILS_API_KEY:
        return "SecurityTrails API key not set"
    try:
        r = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}",
                         headers={'APIKEY': SECURITYTRAILS_API_KEY})
        return r.json()
    except:
        return "Failed"

def get_publicwww_results(domain):
    try:
        url = f"https://publicwww.com/websites/%22{domain}%22/"
        soup = BeautifulSoup(requests.get(url).text, 'html.parser')
        return [a['href'] for a in soup.find_all('a', href=True) if domain in a['href']]
    except:
        return "Failed"

def get_certspotter_info(domain):
    if not CERTSPOTTER_API_KEY:
        return "CertSpotter API key not set"
    try:
        r = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
                         headers={'Authorization': f"Bearer {CERTSPOTTER_API_KEY}"})
        return r.json()
    except:
        return "Failed"

def get_github_repositories(domain):
    try:
        r = requests.get(f"https://api.github.com/search/repositories?q={domain}")
        return r.json()
    except:
        return "Failed"

def get_wayback_machine_snapshots(domain):
    try:
        r = requests.get(f"http://archive.org/wayback/available?url={domain}")
        return r.json() if r.status_code == 200 else "No snapshots"
    except:
        return "Failed"

def get_zoomeye_info(domain):
    if not ZOOMEYE_API_KEY:
        return "ZoomEye API key not set"
    try:
        r = requests.get(f"https://api.zoomeye.org/domain/search?query={domain}",
                         headers={'API-KEY': ZOOMEYE_API_KEY})
        return r.json()
    except:
        return "Failed"

def get_criminal_ip_info(domain):
    if not CRIMINAL_IP_API_KEY:
        return "Criminal-IP API key not set"
    try:
        r = requests.get(f"https://api.criminalip.io/v1/domain/{domain}",
                         headers={'x-api-key': CRIMINAL_IP_API_KEY})
        return r.json()
    except:
        return "Failed"

def get_censys_info(domain):
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return "Censys API key not set"
    try:
        data = {'query': domain, 'fields': ['ip', 'protocols', 'location', 'updated_at']}
        r = requests.post("https://censys.io/api/v1/search/ipv4",
                          auth=(CENSYS_API_ID, CENSYS_API_SECRET), json=data)
        return r.json() if r.status_code == 200 else "No data found"
    except:
        return "Failed"

def get_crtsh_info(domain):
    try:
        r = requests.get(f"https://crt.sh/?q={domain}&output=json")
        return r.json() if r.status_code == 200 else "No certificates found"
    except:
        return "Failed"

def get_abuseipdb_info(ip):
    if not ABUSEIPDB_API_KEY:
        return "AbuseIPDB API key not set"
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'},
                         params={'ipAddress': ip, 'maxAgeInDays': '90'})
        return r.json() if r.status_code == 200 else "No data found"
    except:
        return "Failed"

def validate_ip_availability(ip):
    try:
        socket.gethostbyname(ip)
        return True
    except:
        return False

# ------------------- Main OSINT Function -------------------
def perform_osint(domain):
    report = {}
    report['WHOIS'] = get_domain_info(domain)
    report['DNS'] = get_dns_records(domain)
    report['Social Media'] = get_social_media_profiles(domain)
    report['Shodan'] = get_shodan_info(domain)
    
    # Reverse IPs
    ip_addresses = []
    if isinstance(report['Shodan'], list):
        ip_addresses = [h['ip_str'] for h in report['Shodan'] if 'ip_str' in h]
    report['Reverse IP'] = {ip: get_reverse_ip_lookup(ip) for ip in ip_addresses}

    # Breach & Emails
    report['Breached Data'] = get_breached_data(domain)
    report['Emails'] = get_emails(domain)
    report['Pastebin Mentions'] = get_pastebin_mentions(domain)
    report['SecurityTrails'] = get_securitytrails_info(domain)
    report['PublicWWW'] = get_publicwww_results(domain)
    report['CertSpotter'] = get_certspotter_info(domain)
    report['GitHub'] = get_github_repositories(domain)
    report['Wayback Machine'] = get_wayback_machine_snapshots(domain)
    report['ZoomEye'] = get_zoomeye_info(domain)
    report['Criminal-IP'] = get_criminal_ip_info(domain)
    report['Censys'] = get_censys_info(domain)
    report['crt.sh'] = get_crtsh_info(domain)

    # IP validation & AbuseIPDB
    report['IP Validation'] = {ip: validate_ip_availability(ip) for ip in ip_addresses}
    report['AbuseIPDB'] = {ip: get_abuseipdb_info(ip) for ip in ip_addresses}

    # Save report with datetime serialization
    filename = f"osint_report_{domain}.json"
    with open(filename, "w") as f:
        json.dump(serialize_data(report), f, indent=4)
    print(f"[+] OSINT report saved to {filename}")

# ------------------- Run -------------------
if __name__ == "__main__":
    target = input("Enter target domain: ")
    perform_osint(target)

>>>>>>> 30e8126 (first commit)
