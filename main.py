import re
import requests
import logging
from collections import OrderedDict
from datetime import datetime
from urllib.parse import urlparse
import config  # Ensure config.py exists and is correctly configured

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("function.log", "w", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def parse_template(template_file: str) -> OrderedDict:
    """
    Parse the template file and return an OrderedDict of channels grouped by category.
    
    :param template_file: Path to the template file
    :return: OrderedDict of channels grouped by category
    """
    template_channels = OrderedDict()
    current_category = None
    with open(template_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if "#genre#" in line:
                    current_category = line.split(",")[0].strip()
                    template_channels[current_category] = []
                elif current_category:
                    channel_name = line.split(",")[0].strip()
                    template_channels[current_category].append(channel_name)
    return template_channels

def clean_channel_name(channel_name: str) -> str:
    """
    Clean the channel name by removing special characters and converting to uppercase.
    
    :param channel_name: Original channel name
    :return: Cleaned channel name
    """
    cleaned_name = re.sub(r'[$「」-]', '', channel_name)
    cleaned_name = re.sub(r'\s+', '', cleaned_name)
    cleaned_name = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), cleaned_name)
    return cleaned_name.upper()

def fetch_local_channels(local_file: str) -> OrderedDict:
    """
    Fetch channels from a local file (m3u or txt format).
    
    :param local_file: Path to the local file
    :return: OrderedDict of channels grouped by category
    """
    channels = OrderedDict()
    try:
        with open(local_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:15])
        source_type = "m3u" if is_m3u else "txt"
        logging.info(f"Reading local file {local_file} succeeded, determined as {source_type} format")
        if is_m3u:
            channels.update(parse_m3u_lines(lines))
        else:
            channels.update(parse_txt_lines(lines))
        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"Local file {local_file} processed successfully, containing channel categories: {categories}")
    except Exception as e:
        logging.error(f"Failed to read local file {local_file} ❌, Error: {e}")
    return channels

def fetch_remote_channels(url: str) -> OrderedDict:
    """
    Fetch channels from a remote URL (m3u or txt format).
    
    :param url: URL to fetch channels from
    :return: OrderedDict of channels grouped by category
    """
    channels = OrderedDict()
    try:
        response = requests.get(url)
        response.raise_for_status()
        response.encoding = 'utf-8'
        lines = response.text.split("\n")
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:15])
        source_type = "m3u" if is_m3u else "txt"
        logging.info(f"URL: {url} fetched successfully, determined as {source_type} format")
        if is_m3u:
            channels.update(parse_m3u_lines(lines))
        else:
            channels.update(parse_txt_lines(lines))
        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"URL: {url} processed successfully, containing channel categories: {categories}")
    except requests.RequestException as e:
        logging.error(f"Failed to fetch URL: {url} ❌, Error: {e}")
    return channels

def parse_m3u_lines(lines: List[str]) -> OrderedDict:
    """
    Parse m3u formatted lines into an OrderedDict of channels.
    
    :param lines: List of lines from the m3u file
    :return: OrderedDict of channels grouped by category
    """
    channels = OrderedDict()
    current_category = None
    channel_name = None
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTINF"):
            match = re.search(r'group-title="(.*?)",(.*)', line)
            if match:
                current_category = match.group(1).strip()
                channel_name = match.group(2).strip()
                if channel_name and channel_name.startswith("CCTV"):
                    channel_name = clean_channel_name(channel_name)
                if current_category not in channels:
                    channels[current_category] = []
        elif line and not line.startswith("#"):
            channel_url = line.strip()
            if current_category and channel_name:
                channels[current_category].append((channel_name, channel_url))
    return channels

def parse_txt_lines(lines: List[str]) -> OrderedDict:
    """
    Parse txt formatted lines into an OrderedDict of channels.
    
    :param lines: List of lines from the txt file
    :return: OrderedDict of channels grouped by category
    """
    channels = OrderedDict()
    current_category = None
    for line in lines:
        line = line.strip()
        if "#genre#" in line:
            current_category = line.split(",")[0].strip()
            channels[current_category] = []
        elif current_category:
            match = re.match(r"^(.*?),(.*?)$", line)
            if match:
                channel_name = match.group(1).strip()
                if channel_name and channel_name.startswith("CCTV"):
                    channel_name = clean_channel_name(channel_name)
                channel_urls = match.group(2).strip().split('#')
                for channel_url in channel_urls:
                    channel_url = channel_url.strip()
                    channels[current_category].append((channel_name, channel_url))
            elif line:
                channels[current_category].append((line, ''))
    return channels

def match_channels(template_channels: OrderedDict, all_channels: OrderedDict) -> OrderedDict:
    """
    Match channels from the template with all available channels.
    
    :param template_channels: OrderedDict of template channels
    :param all_channels: OrderedDict of all available channels
    :return: OrderedDict of matched channels
    """
    matched_channels = OrderedDict()
    for category, channel_list in template_channels.items():
        matched_channels[category] = OrderedDict()
        for channel_name in channel_list:
            for online_category, online_channel_list in all_channels.items():
                for online_channel_name, online_channel_url in online_channel_list:
                    if channel_name == online_channel_name:
                        matched_channels[category].setdefault(channel_name, []).append(online_channel_url)
    return matched_channels

def merge_channels(target: OrderedDict, source: OrderedDict) -> None:
    """
    Merge channels from source into target.
    
    :param target: Target OrderedDict to merge into
    :param source: Source OrderedDict to merge from
    """
    for category, channel_list in source.items():
        if category in target:
            target[category].extend(channel_list)
        else:
            target[category] = channel_list

def filter_source_urls(template_file: str) -> Tuple[OrderedDict, OrderedDict]:
    """
    Filter and match channels from various sources based on the template.
    
    :param template_file: Path to the template file
    :return: Tuple of matched channels and template channels
    """
    template_channels = parse_template(template_file)
    all_channels = OrderedDict()
    local_channels = fetch_local_channels("1tv.txt")
    merge_channels(all_channels, local_channels)
    source_urls = config.source_urls
    for url in source_urls:
        remote_channels = fetch_remote_channels(url)
        merge_channels(all_channels, remote_channels)
    matched_channels = match_channels(template_channels, all_channels)
    return matched_channels, template_channels

def is_ipv6(url: str) -> bool:
    """
    Check if the URL is an IPv6 address.
    
    :param url: URL to check
    :return: True if the URL is an IPv6 address, False otherwise
    """
    return re.match(r'^http:\/\/\[[0-9a-fA-F:]+\]', url) is not None

def extract_domain_or_ip(url: str) -> str:
    """
    Extract the domain or IP from a URL.
    
    :param url: URL to extract from
    :return: Extracted domain or IP
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        return domain if domain else ""
    except Exception:
        return ""

def sort_and_filter_urls(urls: List[str], written_urls: set) -> List[str]:
    """
    Sort and filter URLs based on domain and blacklist.
    
    :param urls: List of URLs to sort and filter
    :param written_urls: Set of already written URLs
    :return: List of sorted and filtered URLs
    """
    filtered_urls = [
        url for url in urls
        if url and url not in written_urls and not any(blacklist in url for blacklist in config.url_blacklist)
    ]
    url_domain_pairs = [(url, extract_domain_or_ip(url)) for url in filtered_urls]
    sorted_pairs = sorted(url_domain_pairs, key=lambda x: (x[1], x[0]))
    sorted_urls = [pair[0] for pair in sorted_pairs]
    written_urls.update(sorted_urls)
    return sorted_urls

def add_url_suffix(url: str, index: int, total_urls: int, ip_version: str) -> str:
    """
    Add a suffix to the URL based on its index and IP version.
    
    :param url: Original URL
    :param index: Index of the URL
    :param total_urls: Total number of URLs
    :param ip_version: IP version (IPv4 or IPv6)
    :return: URL with added suffix
    """
    suffix = f"${ip_version}" if total_urls == 1 else f"${ip_version}•线路{index}"
    base_url = url.split('$', 1)[0] if '$' in url else url
    return f"{base_url}{suffix}"

def write_to_files(f_m3u: any, f_txt: any, category: str, channel_name: str, index: int, new_url: str) -> None:
    """
    Write channel information to m3u and txt files.
    
    :param f_m3u: File object for m3u file
    :param f_txt: File object for txt file
    :param category: Channel category
    :param channel_name: Channel name
    :param index: Channel index
    :param new_url: New URL for the channel
    """
    logo_url = f"https://gitee.com/IIII-9306/PAV/raw/master/logos/{channel_name}.png"
    f_m3u.write(f"#EXTINF:-1 tvg-id=\"{index}\" tvg-name=\"{channel_name}\" tvg-logo=\"{logo_url}\" group-title=\"{category}\",{channel_name}\n")
    f_m3u.write(new_url + "\n")
    f_txt.write(f"{channel_name},{new_url}\n")

def updateChannelUrlsM3U(channels: OrderedDict, template_channels: OrderedDict) -> None:
    """
    Update channel URLs and write them to m3u and txt files.
    
    :param channels: OrderedDict of matched channels
    :param template_channels: OrderedDict of template channels
    """
    written_urls_ipv4 = set()
    written_urls_ipv6 = set()
    current_date = datetime.now().strftime("%Y-%m-%d")
    for group in config.announcements:
        for announcement in group['entries']:
            if announcement['name'] is None:
                announcement['name'] = current_date
    with open("live_ipv4.m3u", "w", encoding="utf-8") as f_m3u_ipv4, \
         open("live_ipv4.txt", "w", encoding="utf-8") as f_txt_ipv4, \
         open("live_ipv6.m3u", "w", encoding="utf-8") as f_m3u_ipv6, \
         open("live_ipv6.txt", "w", encoding="utf-8") as f_txt_ipv6:
        f_m3u_ipv4.write(f"""#EXTM3U x-tvg-url={",".join(f'"{epg_url}"' for epg_url in config.epg_urls)}\n""")
        f_m3u_ipv6.write(f"""#EXTM3U x-tvg-url={",".join(f'"{epg_url}"' for epg_url in config.epg_urls)}\n""")
        for group in config.announcements:
            f_txt_ipv4.write(f"{group['channel']},#genre#\n")
            f_txt_ipv6.write(f"{group['channel']},#genre#\n")
            for announcement in group['entries']:
                f_m3u_ipv4.write(f"""#EXTINF:-1 tvg-id="1" tvg-name="{announcement['name']}" tvg-logo="{announcement['logo']}" group-title="{group['channel']}",{announcement['name']}\n""")
                f_m3u_ipv4.write(f"{announcement['url']}\n")
                f_txt_ipv4.write(f"{announcement['name']},{announcement['url']}\n")
                f_m3u_ipv6.write(f"""#EXTINF:-1 tvg-id="1" tvg-name="{announcement['name']}" tvg-logo="{announcement['logo']}" group-title="{group['channel']}",{announcement['name']}\n""")
                f_m3u_ipv6.write(f"{announcement['url']}\n")
                f_txt_ipv6.write(f"{announcement['name']},{announcement['url']}\n")
        for category, channel_list in template_channels.items():
            f_txt_ipv4.write(f"{category},#genre#\n")
            f_txt_ipv6.write(f"{category},#genre#\n")
            if category in channels:
                for channel_name in channel_list:
                    if channel_name in channels[category]:
                        sorted_urls_ipv4 = [url for url in sort_and_filter_urls(channels[category][channel_name], written_urls_ipv4) if not is_ipv6(url)]
                        sorted_urls_ipv6 = [url for url in sort_and_filter_urls(channels[category][channel_name], written_urls_ipv6) if is_ipv6(url)]
                        total_urls_ipv4 = len(sorted_urls_ipv4)
                        total_urls_ipv6 = len(sorted_urls_ipv6)
                        for index, url in enumerate(sorted_urls_ipv4, start=1):
                            new_url = add_url_suffix(url, index, total_urls_ipv4, "IPV4")
                            write_to_files(f_m3u_ipv4, f_txt_ipv4, category, channel_name, index, new_url)
                        for index, url in enumerate(sorted_urls_ipv6, start=1):
                            new_url = add_url_suffix(url, index, total_urls_ipv6, "IPV6")
                            write_to_files(f_m3u_ipv6, f_txt_ipv6, category, channel_name, index, new_url)
        f_txt_ipv4.write("\n")
        f_txt_ipv6.write("\n")

if __name__ == "__main__":
    template_file = "demo.txt"
    channels, template_channels = filter_source_urls(template_file)
    updateChannelUrlsM3U(channels, template_channels)
