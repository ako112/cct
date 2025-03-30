import re
import requests
import logging
from collections import OrderedDict
from datetime import datetime
from urllib.parse import urlparse
import config

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("function.log", "w", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

def parse_template(template_file):
    """解析模板文件"""
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

def clean_channel_name(channel_name):
    """标准化频道名称"""
    cleaned = re.sub(r'[$「」\-]', '', channel_name)
    cleaned = re.sub(r'\s+', '', cleaned)
    cleaned = re.sub(r'(\D+)(\d+)', lambda m: f"{m.group(1)}{int(m.group(2))}", cleaned)
    return cleaned.upper()

def fetch_local_channels(local_file):
    """读取本地频道源"""
    channels = OrderedDict()
    try:
        with open(local_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:5])
        parser = parse_m3u_lines if is_m3u else parse_txt_lines
        channels.update(parser(lines))
        logging.info(f"本地文件解析成功: {local_file}")
    except Exception as e:
        logging.error(f"本地文件错误: {str(e)}")
    return channels

def fetch_remote_channels(url):
    """获取远程频道源"""
    channels = OrderedDict()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()
        is_m3u = any(line.startswith("#EXTINF") for line in lines[:5])
        parser = parse_m3u_lines if is_m3u else parse_txt_lines
        channels.update(parser(lines))
        logging.info(f"远程源成功: {url}")
    except Exception as e:
        logging.error(f"远程源失败: {url} - {str(e)}")
    return channels

def parse_m3u_lines(lines):
    """解析M3U格式"""
    channels = OrderedDict()
    current_category = None
    channel_name = None
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTINF"):
            match = re.search(r'group-title="(.*?)".*?,(.*)', line, re.IGNORECASE)
            if match:
                current_category = match.group(1).strip()
                channel_name = clean_channel_name(match.group(2).strip())
                channels.setdefault(current_category, [])
        elif line and not line.startswith("#") and current_category and channel_name:
            channels[current_category].append((channel_name, line.strip()))
    return channels

def parse_txt_lines(lines):
    """解析TXT格式"""
    channels = OrderedDict()
    current_category = None
    for line in lines:
        line = line.strip()
        if "#genre#" in line:
            current_category = line.split("#genre#")[0].strip()
            channels[current_category] = []
        elif current_category and ',' in line:
            parts = line.split(',', 1)
            name = clean_channel_name(parts[0].strip())
            urls = [u.strip() for u in parts[1].split('#') if u.strip()]
            for url in urls:
                channels[current_category].append((name, url))
    return channels

def match_channels(template, sources):
    """匹配频道"""
    matched = OrderedDict()
    for category, names in template.items():
        matched[category] = OrderedDict()
        for name in names:
            matched_urls = []
            for src_category, channels in sources.items():
                for ch_name, url in channels:
                    if ch_name == name:
                        matched_urls.append(url)
            if matched_urls:
                matched[category][name] = matched_urls
    return matched

def merge_channels(target, source):
    """合并数据"""
    for cat, chs in source.items():
        if cat in target:
            existing_urls = {url for _, url in target[cat]}
            for name, url in chs:
                if url not in existing_urls:
                    target[cat].append((name, url))
        else:
            target[cat] = chs.copy()

def filter_source_urls(template_file):
    """整合数据源"""
    template = parse_template(template_file)
    all_channels = OrderedDict()
    
    local = fetch_local_channels("1tv.txt")
    merge_channels(all_channels, local)
    
    for url in config.source_urls:
        remote = fetch_remote_channels(url)
        merge_channels(all_channels, remote)
    
    return match_channels(template, all_channels), template

def is_ipv6(url):
    """检查IPv6"""
    return re.match(r'^https?://\[[0-9a-fA-F:]+\]', url) is not None

def extract_domain(url):
    """提取域名"""
    try:
        return urlparse(url).hostname or ""
    except:
        return ""

def sort_urls(urls, seen):
    """排序URL"""
    filtered = [
        url for url in urls
        if url and url not in seen 
        and not any(b in url for b in config.url_blacklist)
    ]
    sorted_urls = sorted(filtered, key=lambda x: (extract_domain(x), x))
    seen.update(sorted_urls)
    return sorted_urls

def write_entry(f_m3u, f_txt, category, name, url, index):
    """写入条目"""
    logo = f"https://gitee.com/IIII-9306/PAV/raw/master/logos/{name}.png"
    f_m3u.write(
        f'#EXTINF:-1 tvg-id="{index}" tvg-name="{name}" '
        f'tvg-logo="{logo}" group-title="{category}",{name}\n{url}\n'
    )
    f_txt.write(f"{name},{url}\n")

def generate_playlists(channels, template):
    """生成播放列表"""
    ipv4_seen = set()
    ipv6_seen = set()
    
    with open("live_ipv4.m3u", "w", encoding="utf-8") as f_m3u4, \
         open("live_ipv4.txt", "w", encoding="utf-8") as f_txt4, \
         open("live_ipv6.m3u", "w", encoding="utf-8") as f_m3u6, \
         open("live_ipv6.txt", "w", encoding="utf-8") as f_txt6:

        # 文件头
        epg_header = f'#EXTM3U x-tvg-url="{",".join(config.epg_urls)}"\n'
        f_m3u4.write(epg_header)
        f_m3u6.write(epg_header)
        
        # 公告信息
        for group in config.announcements:
            cat = group['channel']
            f_txt4.write(f"{cat},#genre#\n")
            f_txt6.write(f"{cat},#genre#\n")
            for item in group['entries']:
                write_entry(f_m3u4, f_txt4, cat, item['name'], item['url'], 1)
                write_entry(f_m3u6, f_txt6, cat, item['name'], item['url'], 1)
        
        # 频道数据
        for category, names in template.items():
            f_txt4.write(f"{category},#genre#\n")
            f_txt6.write(f"{category},#genre#\n")
            if category not in channels:
                continue
                
            for name in names:
                if name not in channels[category]:
                    continue
                
                # IPv4处理
                ipv4_urls = [u for u in channels[category][name] if not is_ipv6(u)]
                for idx, url in enumerate(sort_urls(ipv4_urls, ipv4_seen), 1):
                    write_entry(f_m3u4, f_txt4, category, name, url, idx)
                
                # IPv6处理
                ipv6_urls = [u for u in channels[category][name] if is_ipv6(u)]
                for idx, url in enumerate(sort_urls(ipv6_urls, ipv6_seen), 1):
                    write_entry(f_m3u6, f_txt6, category, name, url, idx)

if __name__ == "__main__":
    try:
        matched_data, template_data = filter_source_urls("demo.txt")
        generate_playlists(matched_data, template_data)
        logging.info("运行成功！")
    except Exception as e:
        logging.critical(f"运行失败: {str(e)}", exc_info=True)
