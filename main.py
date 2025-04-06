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
    """
    标准化频道名称，处理CCTV等特殊情况。
    
    :param channel_name: 原始频道名称
    :return: 标准化后的频道名称
    """
    # 转换为大写并去除特殊字符
    normalized = channel_name.upper()
    normalized = re.sub(r'[$「」-]', '', normalized)
    normalized = re.sub(r'\s+', '', normalized)
    
    # 处理CCTV特殊情况
    if normalized.startswith("CCTV"):
        normalized = re.sub(r'(\D*)(\d+)', lambda m: m.group(1) + str(int(m.group(2))), normalized)
        if "综合" in normalized:
            normalized = "CCTV1"
    
    return normalized

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
                    template_channels[current_category].append(normalize_channel_name(channel_name))
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
                channels[current_category].append((normalize_channel_name(channel_name), channel_url))
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
                    channels[current_category].append((normalize_channel_name(channel_name), channel_url))
            elif line:
                channels[current_category].append((normalize_channel_name(line), ''))
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

def filter_source_urls(template_file: str, source_urls_file: str) -> Tuple[OrderedDict, OrderedDict]:
    """
    根据模板从各种来源过滤和匹配频道。
    
    :param template_file: 模板文件路径
    :param source_urls_file: 包含源URL的本地文件路径
    :return: 匹配的频道和模板频道的元组
    """
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
import logging
import re
import requests
from collections import OrderedDict
from typing import List, Dict, Tuple

# 日志记录配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_blacklist(file_path: str) -> set:
    """从文件加载黑名单，返回一个黑名单集合。"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except Exception as e:
        logging.error(f"读取黑名单文件失败❌，错误: {e}")
        return set()

def normalize_channel_name(name: str) -> str:
    """标准化频道名称，去除特殊字符，确保格式一致。"""
    return re.sub(r'\W+', ' ', name).strip().lower()

def clean_channel_name(name: str) -> str:
    """清理频道名称，增加可读性。"""
    return ' '.join(name.split()).strip()

def parse_template(template_file: str) -> OrderedDict:
    """解析模板文件，将频道按类别分组。"""
    channels = OrderedDict()
    with open(template_file, "r", encoding="utf-8") as f:
        current_category = None
        for line in f:
            line = line.strip()
            if line.startswith("#"):
                current_category = line[1:].strip()
                channels[current_category] = []
            elif current_category:
                channels[current_category].append(clean_channel_name(line))
    return channels

def fetch_local_channels(file_path: str) -> OrderedDict:
    """从本地文件读取频道。"""
    channels = OrderedDict()
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            name, url = line.strip().split(",", 1)
            channels[clean_channel_name(name)] = url.strip()
    return channels

def fetch_remote_channels(url: str) -> OrderedDict:
    """从远程 URL 获取频道。"""
    channels = OrderedDict()
    try:
        response = requests.get(url)
        response.raise_for_status()
        for line in response.text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name, url = line.split(",", 1)
                channels[clean_channel_name(name)] = url.strip()
    except Exception as e:
        logging.error(f"无法获取远程频道，URL: {url} 错误: {e}")
    return channels

def match_channels(template_channels: OrderedDict, all_channels: OrderedDict, blacklist: set) -> OrderedDict:
    """将模板中的频道与所有可用频道匹配，并过滤黑名单中的频道。"""
    matched_channels = OrderedDict()
    for category, channel_list in template_channels.items():
        matched_channels[category] = OrderedDict()
        for channel_name in channel_list:
            for online_channel_name, online_channel_url in all_channels.items():
                # 检查频道URL是否在黑名单中
                if online_channel_url in blacklist:
                    logging.info(f"频道 {online_channel_name} 的URL {online_channel_url} 被黑名单过滤，跳过。")
                    continue
                if channel_name == online_channel_name:
                    matched_channels[category][channel_name] = online_channel_url
                    break
    return matched_channels

def merge_channels(all_channels: OrderedDict, new_channels: OrderedDict):
    """将新频道合并到总频道列表中。"""
    for channel_name, url in new_channels.items():
        if channel_name not in all_channels:
            all_channels[channel_name] = url

def write_to_files(channels: OrderedDict):
    """将合并后的频道写入文件。"""
    with open("output.txt", "w", encoding="utf-8") as f:
        for category, channel_list in channels.items():
            f.write(f"#{category}\n")
            for channel_name, url in channel_list.items():
                f.write(f"{channel_name},{url}\n")
                
    logging.info("频道已写入输出文件.")

def filter_source_urls(template_file: str, source_urls_file: str, blacklist_file: str) -> Tuple[OrderedDict, OrderedDict]:
    """根据模板从各种来源过滤和匹配频道，并应用黑名单。"""
    template_channels = parse_template(template_file)
    all_channels = OrderedDict()
    
    # 读取黑名单
    blacklist = load_blacklist(blacklist_file)

    # 读取本地直播源文件
    local_channels = fetch_local_channels("1tv.txt")  # 本地文件名应已知
    merge_channels(all_channels, local_channels)
    
    # 读取包含源URL的本地文件
    with open(source_urls_file, "r", encoding="utf-8") as f:
        source_urls = [line.strip() for line in f if line.strip()]
    
    # 读取并合并远程直播源
    for url in source_urls:
        remote_channels = fetch_remote_channels(url)
        merge_channels(all_channels, remote_channels)
    
    matched_channels = match_channels(template_channels, all_channels, blacklist)
    return matched_channels, template_channels

if __name__ == "__main__":
    template_file = "demo.txt"
    source_urls_file = "source_urls.txt"  # 本地文件，包含多个在线直播源的URL
    blacklist_file = "blacklist.txt"  # 黑名单文件路径

    channels, _ = filter_source_urls(template_file, source_urls_file, blacklist_file)
    write_to_files(channels)

    logging.info("处理完成！")
