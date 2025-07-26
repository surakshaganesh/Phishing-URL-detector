import re
import socket
import ssl
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def extract_features(url):
    features = []
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    # Initialize response and soup
    try:
        response = requests.get(url, timeout=5)
        page_content = response.text
        soup = BeautifulSoup(response.content, 'html.parser')
    except:
        response = None
        page_content = ""
        soup = BeautifulSoup("", 'html.parser')

    # 1. Having IP Address
    try:
        socket.inet_aton(hostname)
        features.append(1)
    except:
        features.append(0)

    # 2. URL Length
    features.append(len(url))

    # 3. Shortening Service
    shortening_services = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly"
    features.append(1 if re.search(shortening_services, url) else 0)

    # 4. Having '@' symbol
    features.append(1 if '@' in url else 0)

    # 5. Double Slash Redirecting
    features.append(1 if url.rfind('//') > 6 else 0)

    # 6. Prefix/Suffix in domain
    features.append(1 if '-' in hostname else 0)

    # 7. Subdomains
    features.append(hostname.count('.'))

    # 8. HTTPS
    features.append(1 if parsed.scheme == 'https' else 0)

    # 9. Domain Registration Length
    try:
        domain_info = whois.whois(hostname)
        expiration = domain_info.expiration_date
        updated = domain_info.updated_date
        if isinstance(expiration, list): expiration = expiration[0]
        if isinstance(updated, list): updated = updated[0]
        reg_days = (expiration - updated).days
        features.append(1 if reg_days >= 365 else 0)
    except:
        features.append(0)

    # 10. Favicon
    try:
        icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
        if icon and hostname not in icon.get('href', ''):
            features.append(1)
        else:
            features.append(0)
    except:
        features.append(1)

    # 11. Non-Standard Port
    try:
        port = parsed.port
        features.append(1 if port and port not in [80, 443] else 0)
    except:
        features.append(0)

    # 12. HTTPS in domain part
    features.append(1 if 'https' in hostname else 0)

    # 13. Request URL (External content loading)
    try:
        external_count = 0
        total = 0
        for tag in soup.find_all(['img', 'audio', 'embed', 'iframe']):
            src = tag.get('src')
            if src:
                total += 1
                if hostname not in src:
                    external_count += 1
        ratio = external_count / total if total > 0 else 0
        features.append(1 if ratio > 0.5 else 0)
    except:
        features.append(1)

    # 14. Anchor tags
    try:
        unsafe = 0
        total = 0
        for a in soup.find_all('a', href=True):
            total += 1
            if '#' in a['href'] or 'javascript:' in a['href'] or 'mailto:' in a['href']:
                unsafe += 1
        ratio = unsafe / total if total > 0 else 0
        features.append(1 if ratio > 0.5 else 0)
    except:
        features.append(1)

    # 15. SFH (Server Form Handler)
    try:
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action == "" or action == "about:blank" or hostname not in action:
                features.append(1)
                break
        else:
            features.append(0)
    except:
        features.append(1)

    # 16. Submitting to Email
    try:
        features.append(1 if re.findall(r"[mail\(\)|mailto:?]", page_content) else 0)
    except:
        features.append(1)

    # 17. Abnormal URL
    features.append(0 if url.startswith("http") else 1)

    # 18. Website Forwarding
    try:
        if response and len(response.history) > 2:
            features.append(1)
        else:
            features.append(0)
    except:
        features.append(1)

    # 19. Status Bar Customization
    features.append(1 if re.findall(r"onmouseover=\"window\.status=", page_content) else 0)

    # 20. Disabling Right Click
    features.append(1 if re.findall(r"event.button ?== ?2", page_content) else 0)

    # 21. Using Pop-up Window
    features.append(1 if re.findall(r"alert\(", page_content) else 0)

    # 22. Iframe Redirection
    features.append(1 if re.findall(r"<iframe[^>]+>", page_content) else 0)

    # 23. Age of Domain
    try:
        creation = domain_info.creation_date
        if isinstance(creation, list): creation = creation[0]
        age_days = (datetime.now() - creation).days
        features.append(1 if age_days < 180 else 0)
    except:
        features.append(1)

    # 24. DNS Record
    try:
        socket.gethostbyname(hostname)
        features.append(0)
    except:
        features.append(1)

    # 25. Web Traffic
    try:
        rank = requests.get(f"https://www.alexa.com/siteinfo/{hostname}").text
        features.append(1 if "No Data" in rank else 0)
    except:
        features.append(1)

    # 26–48: Pad with 0s
    while len(features) < 48:
        features.append(0)

    return features
