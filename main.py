import re
import requests
import logging
from collections import OrderedDict, defaultdict
from datetime import datetime
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

# 黑名单文件名
BLACKLIST_FILE = "blacklist.txt"

# 初始化黑名单为空集合
BLACKLIST = set()

def load_blacklist(blacklist_file: str) -> set:
    """从文件中加载黑名单地址。"""
    blacklist = set()
    try:
        with open(blacklist_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):  # 忽略空行和注释行
                    blacklist.add(line)
        logging.info(f"成功加载黑名单文件: {blacklist_file}, 共 {len(blacklist)} 条记录")
    except FileNotFoundError:
        logging.warning(f"黑名单文件未找到: {blacklist_file}")
    except Exception as e:
        logging.error(f"加载黑名单文件 {blacklist_file} 失败: {e}")
    return blacklist

# 标准化频道名称
def normalize_channel_name(channel_name: str) -> str:
    normalized = channel_name.upper()
    normalized = re.sub(r'[$「」-]', '', normalized)
    normalized = re.sub(r'\s+', '', normalized)

    if normalized.startswith("CCTV"):
        normalized = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), normalized)
        if "综合" in normalized:
            normalized = "CCTV1"

    return normalized

# 解析模板文件
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

# 清理频道名称
def clean_channel_name(channel_name: str) -> str:
    cleaned_name = re.sub(r'[$「」-]', '', channel_name)
    cleaned_name = re.sub(r'\s+', '', cleaned_name)
    cleaned_name = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), cleaned_name)
    return cleaned_name.upper()

# 从本地文件获取频道
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

# 从远程URL获取频道
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

        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"URL: {url} 处理成功,包含频道分类: {categories}")
    except requests.RequestException as e:
        logging.error(f"获取URL: {url} 失败❌, 错误: {e}")
    return channels

# 解析m3u格式
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

                if current_category not in channels:
                    channels[current_category] = []
        elif line and not line.startswith("#"):
            channel_url = line.strip()
            if current_category and channel_name:
                channels[current_category].append((normalize_channel_name(channel_name), channel_url))
    return channels

# 解析txt格式
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
                channel_urls = match.group(2).strip().split('#')

                for channel_url in channel_urls:
                    channel_url = channel_url.strip()
                    channels[current_category].append((normalize_channel_name(channel_name), channel_url))
            elif line:
                channels[current_category].append((normalize_channel_name(line), ''))
    return channels

# 匹配频道
def match_channels(template_channels: OrderedDict, all_channels: OrderedDict) -> OrderedDict:
    matched_channels = OrderedDict()
    for category, channel_list in template_channels.items():
        matched_channels[category] = OrderedDict()
        for channel_name in channel_list:
            for online_category, online_channel_list in all_channels.items():
                for online_channel_name, online_channel_url in online_channel_list:
                    if online_channel_url in BLACKLIST:
                        continue
                    if channel_name == online_channel_name:
                        matched_channels[category].setdefault(channel_name, []).append(online_channel_url)
    return matched_channels

# 合并频道
def merge_channels(target: OrderedDict, source: OrderedDict) -> None:
    for category, channel_list in source.items():
        if category not in target:
            target[category] = OrderedDict()

        for channel_name, urls in channel_list:  # 修改这里，source 的 channel_list 是 (name, url) 元组列表
            if category not in target or channel_name not in target[category]:
                target[category][channel_name] = [urls]
            else:
                target[category][channel_name].append(urls)
                target[category][channel_name] = list(set(target[category][channel_name]))

def filter_source_urls(template_file: str, source_urls_file: str) -> Tuple[OrderedDict, OrderedDict]:
    global BLACKLIST
    BLACKLIST = load_blacklist(BLACKLIST_FILE)  # 在开始时加载黑名单

    template_channels = parse_template(template_file)
    all_channels = OrderedDict()

    local_channels = fetch_local_channels("1tv.txt")
    merge_channels(all_channels, local_channels)

    with open(source_urls_file, "r", encoding="utf-8") as f:
        source_urls = [line.strip() for line in f if line.strip()]

    for url in source_urls:
        remote_channels = fetch_remote_channels(url)
        merge_channels(all_channels, remote_channels)

    matched_channels = match_channels(template_channels, all_channels)
    return matched_channels, template_channels

# 检查是否是IPv6地址
def is_ipv6(url: str) -> bool:
    return re.match(r'^http:\/\/\[[0-9a-fA-F:]+\]', url) is not None

# 写入文件
def write_to_files(channels: OrderedDict) -> None:
    seen_ipv4 = defaultdict(set)
    seen_ipv6 = defaultdict(set)

    with open("ipv4.txt", "w", encoding="utf-8") as f_ipv4_txt, \
         open("ipv6.txt", "w", encoding="utf-8") as f_ipv6_txt, \
         open("ipv4.m3u", "w", encoding="utf-8") as f_ipv4_m3u, \
         open("ipv6.m3u", "w", encoding="utf-8") as f_ipv6_m3u:

        f_ipv4_m3u.write("#EXTM3U\n")
        f_ipv6_m3u.write("#EXTM3U\n")

        for category, channel_dict in channels.items():
            f_ipv4_txt.write(f"{category},#genre#\n")
            f_ipv6_txt.write(f"{category},#genre#\n")

            for channel_name, channel_urls in channel_dict.items():
                unique_ipv4_urls = []
                unique_ipv6_urls = []

                for url in channel_urls:
                    if url in BLACKLIST:
                        continue
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
