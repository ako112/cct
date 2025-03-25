import re
import requests
import logging
from collections import OrderedDict
from datetime import datetime
import config
from urllib.parse import urlparse  # 新增：用于解析 URL

# 日志记录（保持不变）
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("function.log", "w", encoding="utf-8"), logging.StreamHandler()])

# 其余函数保持不变，直到 sort_and_filter_urls
# 这里只展示修改的部分，其他函数如 parse_template, clean_channel_name 等保持原样

def extract_domain_or_ip(url):
    """从 URL 中提取域名或 IP 地址"""
    try:
        parsed = urlparse(url)
        domain = parsed.hostname  # 提取域名或 IP
        return domain if domain else ""
    except Exception:
        return ""

def sort_and_filter_urls(urls, written_urls):
    """优化排序：按域名或 IP 分组并排序"""
    # 初步过滤：去重和黑名单
    filtered_urls = [
        url for url in urls
        if url and url not in written_urls and not any(blacklist in url for blacklist in config.url_blacklist)
    ]

    # 提取每个 URL 的域名或 IP，并创建 (url, domain) 对
    url_domain_pairs = [(url, extract_domain_or_ip(url)) for url in filtered_urls]

    # 按域名/IP 排序，相同域名/IP 的 URL 排在一起
    sorted_pairs = sorted(url_domain_pairs, key=lambda x: (x[1], x[0]))
    # x[1] 是域名/IP，确保相同域名/IP 聚集
    # x[0] 是原始 URL，作为次级排序键，确保相同域名内的顺序稳定

    # 提取排序后的 URL 列表
    sorted_urls = [pair[0] for pair in sorted_pairs]
    written_urls.update(sorted_urls)
    return sorted_urls

def add_url_suffix(url, index, total_urls, ip_version):
    # 添加URL后缀（保持不变）
    suffix = f"${ip_version}" if total_urls == 1 else f"${ip_version}•线路{index}"
    base_url = url.split('$', 1)[0] if '$' in url else url
    return f"{base_url}{suffix}"

def write_to_files(f_m3u, f_txt, category, channel_name, index, new_url):
    # 写入M3U和TXT文件（保持不变）
    logo_url = f"https://gitee.com/IIII-9306/PAV/raw/master/logos/{channel_name}.png"
    f_m3u.write(f"#EXTINF:-1 tvg-id=\"{index}\" tvg-name=\"{channel_name}\" tvg-logo=\"{logo_url}\" group-title=\"{category}\",{channel_name}\n")
    f_m3u.write(new_url + "\n")
    f_txt.write(f"{channel_name},{new_url}\n")

def updateChannelUrlsM3U(channels, template_channels):
    # 更新频道URL到M3U和TXT文件中（略作调整以适配新排序）
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
