import re
import requests
import logging
from collections import OrderedDict, defaultdict
from datetime import datetime
from typing import List, Dict, Tuple

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("function.log", "w", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

url_blacklist = [
    "http://example.com/blacklisted",  # 示例黑名单URL
    # 其他黑名单URL
]

def is_blacklisted(url: str) -> bool:
    """检查URL是否在黑名单中"""
    return any(blacklisted in url for blacklisted in url_blacklist)

def normalize_channel_name(channel_name: str) -> str:
    # ... 之前的 normalize_channel_name 内容同前 ...

def parse_template(template_file: str) -> OrderedDict:
    # ... 之前的 parse_template 内容同前 ...

def fetch_local_channels(local_file: str) -> OrderedDict:
    # ... 之前的 fetch_local_channels 内容同前 ...

def fetch_remote_channels(url: str) -> OrderedDict:
    """从远程URL(支持m3u或txt格式)获取频道，如果在黑名单中则跳过"""
    channels = OrderedDict()
    if is_blacklisted(url):
        logging.warning(f"URL {url} 被列入黑名单，跳过。")
        return channels

    try:
        response = requests.get(url)
        response.raise_for_status()
        response.encoding = 'utf-8'
        lines = response.text.split("\n")
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:15])
        logging.info(f"网址: {url} 获取成功, 判断为{'m3u' if is_m3u else 'txt'}格式")
        
        if is_m3u:
            channels.update(parse_m3u_lines(lines))
        else:
            channels.update(parse_txt_lines(lines, is_remote=True))  # 指示这是远程源
        
        if channels:
            categories = ", ".join(channels.keys())
            logging.info(f"网址: {url} 处理成功, 包含频道分类: {categories}")
    except requests.RequestException as e:
        logging.error(f"获取网址: {url} 失败❌, 错误: {e}")
    
    return channels

def parse_m3u_lines(lines: List[str]) -> OrderedDict:
    # ... 之前的 parse_m3u_lines 内容同前 ...

def parse_txt_lines(lines: List[str], is_remote: bool = False) -> OrderedDict:
    """将txt格式的行解析为频道 OrderedDict，支持标记远程源"""
    channels = OrderedDict()
    current_category = None
    for line in lines:
        line = line.strip()
        if "#genre#" in line:
            current_category = line.split(",")[0].strip()
            if current_category not in channels:
                channels[current_category] = []

        elif current_category:
            match = re.match(r"^(.*?),(.*?)$", line)
            if match:
                channel_name = match.group(1).strip()
                channel_urls = match.group(2).strip().split('#')
                for channel_url in channel_urls:
                    channel_url = channel_url.strip()
                    if is_remote and not is_blacklisted(channel_url):  # 远程情况下检查URL是否在黑名单中
                        channels[current_category].append((normalize_channel_name(channel_name), channel_url))

            elif line:
                channels[current_category].append((normalize_channel_name(line), ''))

    return channels

def match_channels(template_channels: OrderedDict, all_channels: OrderedDict) -> OrderedDict:
    # ... 之前的 match_channels 内容同前 ...

def merge_channels(target: OrderedDict, source: OrderedDict) -> None:
    # ... 之前的 merge_channels 内容同前 ...

def filter_source_urls(template_file: str, source_urls_file: str) -> Tuple[OrderedDict, OrderedDict]:
    template_channels = parse_template(template_file)
    all_channels = OrderedDict()

    # 读取本地直播源文件
    local_channels = fetch_local_channels("1tv.txt")
    merge_channels(all_channels, local_channels)
    
    # 读取包含源URL的本地文件
    with open(source_urls_file, "r", encoding="utf-8") as f:
        source_urls = [line.strip() for line in f if line.strip()]
    
    # 读取并合并远程直播源
    for url in source_urls:
        remote_channels = fetch_remote_channels(url)
        merge_channels(all_channels, remote_channels)
    
    matched_channels = match_channels(template_channels, all_channels)
    return matched_channels, template_channels

def is_ipv6(url: str) -> bool:
    # ... 之前的 is_ipv6 内容同前 ...

def write_to_files(channels: OrderedDict) -> None:
    # ... 之前的 write_to_files 内容同前 ...

if __name__ == "__main__":
    template_file = "demo.txt"
    source_urls_file = "source_urls.txt"  # 本地文件，包含多个在线直播源的URL

    channels, _ = filter_source_urls(template_file, source_urls_file)
    write_to_files(channels)

    logging.info("合并后的频道已写入IPv4和IPv6的TXT和M3U文件")
