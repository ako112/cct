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
                channel_name = match.group(1).strip
