import re
import requests
import logging
from collections import OrderedDict
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional
import config  # 确保 config.py 存在并正确配置

# 设置日志记录
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
    解析模板文件并返回按类别分组的频道 OrderedDict。
    
    :param template_file: 模板文件路径
    :return: 按类别分组的频道 OrderedDict
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
    清理频道名称,删除特殊字符并转换为大写。
    
    :param channel_name: 原始频道名称
    :return: 清理后的频道名称
    """
    cleaned_name = re.sub(r'[$「」-]', '', channel_name)
    cleaned_name = re.sub(r'\s+', '', cleaned_name)
    cleaned_name = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), cleaned_name)
    return cleaned_name.upper()

def fetch_local_channels(local_file: str) -> OrderedDict:
    """
    从本地文件(支持m3u或txt格式)获取频道。
    
    :param local_file: 本地文件路径
    :return: 按类别分组的频道 OrderedDict
    """
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
    """
    从远程URL(支持m3u或txt格式)获取频道。
    
    :param url: 获取频道的URL
    :return: 按类别分组的频道 OrderedDict
    """
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

def parse_m3u_lines(lines: List[str]) -> OrderedDict:
    """
    将m3u格式的行解析为频道 OrderedDict。
    
    :param lines: m3u文件的行列表
    :return: 按类别分组的频道 OrderedDict
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
    将txt格式的行解析为频道 OrderedDict。
    
    :param lines: txt文件的行列表
    :return: 按类别分组的频道 OrderedDict
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
    将模板中的频道与所有可用频道匹配。
    
    :param template_channels: 模板频道的 OrderedDict
    :param all_channels: 所有可用频道的 OrderedDict
    :return: 匹配的频道 OrderedDict
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
    将源频道合并到目标频道中。
    
    :param target: 要合并到的目标 OrderedDict
    :param source: 要合并的源 OrderedDict
    """
    for category, channel_list in source.items():
        if category in target:
            target[category].extend(channel_list)
        else:
            target[category] = channel_list

def filter_source_urls(template_file: str) -> Tuple[OrderedDict, OrderedDict]:
    """
    根据模板从各种来源过滤和匹配频道。
    
    :param template_file: 模板文件路径
    :return: 匹配的频道和模板频道的元组
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
    检查URL是否为IPv6地址。
    
    :param url: 要检查的URL
    :return: 如果URL是IPv6地址则返回True,否则返回False
    """
    return re.match(r'^http:\/\/\[[0-9a-fA-F:]+\]', url) is not None

def extract_domain_or_ip(url: str) -> str:
    """
    从URL中提取域名或IP。
    
    :param url: 要提取的URL
    :return: 提取的域名或IP
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        return domain if domain else ""
    except Exception:
        return ""

def sort_and_filter_urls(urls: List[str], written_urls: set) -> List[str]:
    """
    根据域名和黑名单排序和过滤URL。
    
    :param urls: 要排序和过滤的URL列表
    :param written_urls: 已写入的URL集合
    :return: 排序和过滤后的URL列表
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
    修改后的函数，直接返回原始URL，不添加任何后缀
    
    :param url: 原始URL
    :param index: URL的索引（不再使用）
    :param total_urls: URL总数（不再使用）
    :param ip_version: IP版本（不再使用）
    :return: 原始URL（去除已有后缀）
    """
    # 分割URL，去除可能已存在的后缀
    base_url = url.split('$', 1)[0] if '$' in url else url
    return base_url

def write_to_files(f_m3u: any, f_txt: any, category: str, channel_name: str, index: int, new_url: str) -> None:
    """
    将频道信息写入m3u和txt文件。
    
    :param f_m3u: m3u文件的文件对象
    :param f_txt: txt文件的文件对象
    :param category: 频道分类
    :param channel_name: 频道名称
    :param index: 频道索引
    :param new_url: 频道的新URL
    """
    logo_url = f"https://gitee.com/IIII-9306/PAV/raw/master/logos/{channel_name}.png"
    f_m3u.write(f"#EXTINF:-1 tvg-id=\"{index}\" tvg-name=\"{channel_name}\" tvg-logo=\"{logo_url}\" group-title=\"{category}\",{channel_name}\n")
    f_m3u.write(new_url + "\n")
    f_txt.write(f"{channel_name},{new_url}\n")

def updateChannelUrlsM3U(channels: OrderedDict, template_channels: OrderedDict) -> None:
    """
    更新频道URL并将其写入m3u和txt文件。
    
    :param channels: 匹配的频道 OrderedDict
    :param template_channels: 模板频道 OrderedDict
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
