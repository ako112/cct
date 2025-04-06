import logging
from collections import defaultdict, OrderedDict
from typing import Dict, Tuple, List

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def filter_source_urls(template_file: str, source_urls_file: str, blacklist_file: str) -> Tuple[OrderedDict, List[str]]:
    """根据模板文件和源 URL 文件过滤源 URL，返回合并后的频道信息和未找到的 URL。"""
    channels = OrderedDict()
    
    # 读取黑名单
    with open(blacklist_file, 'r', encoding='utf-8') as f:
        blacklist = {line.strip() for line in f if line.strip()}
    
    # 读取源 URL
    with open(source_urls_file, 'r', encoding='utf-8') as f:
        source_urls = [line.strip() for line in f if line.strip()]
    
    # 处理模板文件，合并频道信息
    with open(template_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line in blacklist:
                continue
            
            for source in source_urls:
                if source in line:
                    # 假设频道信息格式为 "频道名称,URL,类型"
                    name, url, ip_type = line.split(',')
                    if ip_type not in ['ipv4', 'ipv6']:
                        continue
                    if name not in channels:
                        channels[name] = {}
                    channels[name] = {'url': url, 'type': ip_type}
                    break
    
    logging.info("源 URLs 处理完成.")
    return channels, []

def write_to_files(channels: OrderedDict):
    """将合并后的频道信息写入IPv4和IPv6的TXT和M3U文件。"""
    seen_ipv4 = defaultdict(set)
    seen_ipv6 = defaultdict(set)

    with open("ipv4.txt", "w", encoding="utf-8") as f_ipv4_txt, \
         open("ipv6.txt", "w", encoding="utf-8") as f_ipv6_txt, \
         open("ipv4.m3u", "w", encoding="utf-8") as f_ipv4_m3u, \
         open("ipv6.m3u", "w", encoding="utf-8") as f_ipv6_m3u:

        f_ipv4_m3u.write("#EXTM3U\n")
        f_ipv6_m3u.write("#EXTM3U\n")

        for channel_name, info in channels.items():
            url = info['url']
            ip_type = info['type']
            
            if ip_type == 'ipv4':
                if url not in seen_ipv4[channel_name]:
                    f_ipv4_txt.write(f"{channel_name},{url}\n")
                    f_ipv4_m3u.write(f"#EXTINF:-1,{channel_name}\n{url}\n")
                    seen_ipv4[channel_name].add(url)

            elif ip_type == 'ipv6':
                if url not in seen_ipv6[channel_name]:
                    f_ipv6_txt.write(f"{channel_name},{url}\n")
                    f_ipv6_m3u.write(f"#EXTINF:-1,{channel_name}\n{url}\n")
                    seen_ipv6[channel_name].add(url)

    logging.info("频道信息已写入到文件。")

if __name__ == "__main__":
    template_file = "demo.txt"
    source_urls_file = "source_urls.txt"
    blacklist_file = "blacklist.txt"

    logging.info("开始处理频道...")
    
    channels, _ = filter_source_urls(template_file, source_urls_file, blacklist_file)
    
    if channels:
        write_to_files(channels)
        logging.info("处理完成，频道已写入输出文件.") 
    else:
        logging.warning("未找到任何符合条件的频道。")
