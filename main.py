import re
import requests
import logging
from collections import OrderedDict, defaultdict
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("function.log", "w", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def normalize_channel_name(channel_name: str) -> str:
    normalized = channel_name.upper()
    normalized = re.sub(r'[$「」-]', '', normalized)
    normalized = re.sub(r'\s+', '', normalized)
    
    if normalized.startswith("CCTV"):
        normalized = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), normalized)
        if "综合" in normalized:
            normalized = "CCTV1"
    
    return normalized

def parse_template(template_file: str) -> OrderedDict:
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
                    template_channels[current_category].append(normalize_channel_name(channel_name))
    return template_channels

def clean_channel_name(channel_name: str) -> str:
    cleaned_name = re.sub(r'[$「」-]', '', channel_name)
    cleaned_name = re.sub(r'\s+', '', cleaned_name)
    cleaned_name = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), cleaned_name)
    return cleaned_name.upper()

def fetch_local_channels(local_file: str) -> OrderedDict:
    channels = OrderedDict()
    try:
        with open(local_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:15])
        source_type = "m3u" if is_m3u else "txt"
        logging.info(f"读取本地文件 {local_file} 成功,判断为{source_type}格式")
        if is_m3u:
            channels.update(parse_m3u_lines(lines))
        else:
            channels.update(parse_txt_lines(lines))
        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"本地文件 {local_file} 处理成功,包含频道分类: {categories}")
    except Exception as e:
        logging.error(f"读取本地文件 {local_file} 失败❌, 错误: {e}")
    return channels

def fetch_remote_channels(url: str) -> OrderedDict:
    channels = OrderedDict()
    try:
        response = requests.get(url)
        response.raise_for_status()
        response.encoding = 'utf-8'
        lines = response.text.split("\n")
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:15])
        source_type = "m3u" if is_m3u else "txt"
        logging.info(f"URL: {url} 获取成功,判断为{source_type}格式")
        if is_m3u:
            channels.update(parse_m3u_lines(lines))
        else:
            channels.update(parse_txt_lines(lines))
        
        # 过滤掉黑名单中的URL
        channels = filter_blacklisted_channels(channels)

        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"URL: {url} 处理成功,包含频道分类: {categories}")
    except requests.RequestException as e:
        logging.error(f"获取URL: {url} 失败❌, 错误: {e}")
    return channels

def filter_blacklisted_channels(channels: OrderedDict) -> OrderedDict:
    """过滤掉黑名单中的频道"""
    filtered_channels = OrderedDict()
    for category, channel_list in channels.items():
        filtered_channels[category] = [(name, url) for name, url in channel_list if url not in BLACKLISTED_URLS]
        if not filtered_channels[category]:  # 如果过滤后没有频道，移除该类别
            del filtered_channels[category]
    return filtered_channels

def parse_m3u_lines(lines: List[str]) -> OrderedDict:
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
                channels[current_category].append((normalize_channel_name(channel_name), channel_url))
    return channels

def parse_txt_lines(lines: List[str]) -> OrderedDict:
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
                    channels[current_category].append((normalize_channel_name(channel_name), channel_url))
            elif line:
                channels[current_category].append((normalize_channel_name(line), ''))
    return channels

def match_channels(template_channels: OrderedDict, all_channels: OrderedDict) -> OrderedDict:
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
    for category, channel_list in source.items():
        if category in target:
            target[category].extend(channel_list)
        else:
            target[category] = channel_list

def filter_source_urls(template_file: str, source_urls_file: str) -> Tuple[OrderedDict, OrderedDict]:
    template_channels = parse_template(template_file)
    all_channels = OrderedDict()
    
    # 分开直播源和黑名单
    live_urls = []
    blacklisted_urls = []
    with open(source_urls_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and line.startswith("#"):
                blacklisted_urls.append(line[1:].strip())  # 以#开头的行视为黑名单
            else:
                live_urls.append(line)  # 其他视为直播源

    global BLACKLISTED_URLS
    BLACKLISTED_URLS = set(blacklisted_urls)  # 将黑名单转换为集合用于加快查询

    # 读取本地直播源文件
    local_channels = fetch_local_channels("1tv.txt")
    merge_channels(all_channels, local_channels)
    
    # 读取并合并远程直播源
    for url in live_urls:
        remote_channels = fetch_remote_channels(url)
        merge_channels(all_channels, remote_channels)
    
    matched_channels = match_channels(template_channels, all_channels)
    return matched_channels, template_channels

def is_ipv6(url: str) -> bool:
    return re.match(r'^http:\/\/\[[0-9a-fA-F:]+\]', url) is not None

def write_to_files(channels: OrderedDict) -> None:
    seen_ipv4 = defaultdict(set)
    seen_ipv6 = defaultdict(set)

    with open("ipv4.txt", "w", encoding="utf-8") as f_ipv4_txt, \
         open("ipv6.txt", "w", encoding="utf-8") as f_ipv6_txt, \
         open("ipv4.m3u", "w", encoding="utf-8") as f_ipv4_m3u, \
         open("ipv6.m3u", "w", encoding="utf-8") as f_ipv6_m3u:

        f_ipv4_m3u.write("#EXTM3U\n")
        f_ipv6_m3u.write("#EXTM3U\n")

        for category, channel_list in channels.items():
            f_ipv4_txt.write(f"{category},#genre#\n")
            f_ipv6_txt.write(f"{category},#genre#\n")

            for channel_name, channel_urls in channel_list.items():
                unique_ipv4_urls = []
                unique_ipv6_urls = []

                for url in channel_urls:
                    if is_ipv6(url):
                        if url not in seen_ipv6[channel_name]:
                            seen_ipv6[channel_name].add(url)
                            unique_ipv6_urls.append(url)
                    else:
                        if url not in seen_ipv4[channel_name]:
                            seen_ipv4[channel_name].add(url)
                            unique_ipv4_urls.append(url)

                for url in unique_ipv4_urls:
                    f_ipv4_txt.write(f"{channel_name},{url}\n")
                    f_ipv4_m3u.write(f'#EXTINF:-1 group-title="{category}",{channel_name}\n')
                    f_ipv4_m3u.write(f'{url}\n')

                for url in unique_ipv6_urls:
                    f_ipv6_txt.write(f"{channel_name},{url}\n")
                    f_ipv6_m3u.write(f'#EXTINF:-1 group-title="{category}",{channel_name}\n')
                    f_ipv6_m3u.write(f'{url}\n')

        f_ipv4_txt.write("\n")
        f_ipv6_txt.write("\n")

if __name__ == "__main__":
    template_file = "demo.txt"
    source_urls_file = "source_urls.txt"  # 本地文件，包含多个在线直播源的URL

    channels, _ = filter_source_urls(template_file, source_urls_file)
    write_to_files(channels)

    logging.info("合并后的频道已写入IPv4和IPv6的TXT和M3U文件")
