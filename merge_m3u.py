import sys
import subprocess
import requests
import socket
import urllib.parse
import time

# 加载 config.py 中的远程直播源 URL 和黑名单
def load_config(config_file):
    with open(config_file, "r", encoding="utf-8") as f:
        config_content = f.read()
    local_vars = {}
    exec(config_content, {}, local_vars)
    return local_vars.get("source_urls", []), local_vars.get("url_blacklist", [])

# 测试远程直播源文件的可用性
def test_remote_source(url, timeout=5):
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        if response.status_code == 200:
            print(f"远程直播源文件 {url} 可用")
            return True
        else:
            print(f"远程直播源文件 {url} 不可用，状态码: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"远程直播源文件 {url} 不可用，错误: {e}")
        return False

# 下载远程直播源文件（只处理 M3U 和 TXT 格式）
def download_remote_sources(remote_sources):
    downloaded_files = []
    for i, url in enumerate(remote_sources):
        # 跳过注释掉的 URL
        if url.strip().startswith("#"):
            continue
        # 只处理 M3U 和 TXT 格式的直播源
        if not (url.lower().endswith(".m3u") or url.lower().endswith(".txt")):
            print(f"跳过非 M3U/TXT 格式的 URL: {url}")
            continue
        # 测试直播源文件可用性
        if not test_remote_source(url):
            continue  # 跳过不可用的直播源文件
        # 根据 URL 后缀确定文件名
        if url.endswith(".txt"):
            filename = f"remote{i}.txt"
        elif url.endswith(".m3u"):
            filename = f"remote{i}.m3u"
        else:
            filename = f"remote{i}.unknown"
        # 使用 curl 下载文件
        try:
            subprocess.run(["curl", "-o", filename, url], check=True)
            downloaded_files.append(filename)
        except subprocess.CalledProcessError:
            print(f"警告: 无法下载 {url}，跳过此文件")
            continue
    return downloaded_files

# 解析 URL 的 IP 版本（IPv4 或 IPv6）
def get_ip_version(url):
    try:
        # 解析 URL 的主机名
        hostname = urllib.parse.urlparse(url).hostname
        if not hostname:
            return None
        # 解析主机名的 IP 地址
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in addr_info:
            ip = info[4][0]
            if ":" in ip:  # IPv6 地址包含冒号
                return "ipv6"
            else:  # IPv4 地址是点分十进制
                return "ipv4"
        return None
    except (socket.gaierror, ValueError) as e:
        print(f"无法解析 URL {url} 的 IP 版本，错误: {e}")
        return None

# 检查 URL 是否在黑名单中
def is_url_blacklisted(url, blacklist):
    return any(blacklisted in url for blacklisted in blacklist)

def merge_m3u(local_file, remote_files, output_ipv4_file, output_ipv6_file, url_blacklist):
    # 读取本地直播源文件（1tv.txt）
    with open(local_file, "r", encoding="utf-8") as f:
        local_lines = f.readlines()

    # 读取所有远程直播源文件
    remote_lines_list = []
    for remote_file in remote_files:
        with open(remote_file, "r", encoding="utf-8") as f:
            remote_lines_list.append(f.readlines())

    # 分别存储 IPv4 和 IPv6 的直播源
    ipv4_lines = ["#EXTM3U\n"]
    ipv6_lines = ["#EXTM3U\n"]
    seen_urls_ipv4 = set()  # 用于去重 IPv4 直播源
    seen_urls_ipv6 = set()  # 用于去重 IPv6 直播源

    # 处理本地文件（1tv.txt），不测试速度，假设同时包含在 IPv4 和 IPv6 文件中
    group_title = "未知分组"  # 默认分组
    for line in local_lines:
        line = line.strip()
        if not line:
            continue
        if line.endswith(",#genre#"):
            # 提取分组名称
            group_title = line.replace(",#genre#", "")
            continue
        # 假设每行是 "频道名称,URL" 格式
        if "," in line:
            channel_name, url = line.split(",", 1)
            channel_name = channel_name.strip()
            url = url.strip()
            if url.startswith("http"):
                # 检查是否在黑名单中
                if is_url_blacklisted(url, url_blacklist):
                    print(f"跳过黑名单中的 URL: {url}")
                    continue
                # 本地直播源同时添加到 IPv4 和 IPv6 文件
                entry = f'#EXTINF:-1 group-title="{group_title}",{channel_name}\n{url}\n'
                if url not in seen_urls_ipv4:
                    ipv4_lines.append(entry)
                    seen_urls_ipv4.add(url)
                if url not in seen_urls_ipv6:
                    ipv6_lines.append(entry)
                    seen_urls_ipv6.add(url)

    # 处理远程文件
    for remote_lines in remote_lines_list:
        group_title = "未知分组"  # 默认分组
        previous_line = ""
        for line in remote_lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#EXTM3U"):
                continue  # 跳过重复的 #EXTM3U
            elif line.endswith(",#genre#"):
                # 远程 TXT 文件的分组标记
                group_title = line.replace(",#genre#", "")
                continue
            elif line.startswith("#EXTINF"):
                # 远程 M3U 文件的 #EXTINF 行
                previous_line = line
                continue
            elif "," in line and not line.startswith("http"):
                # 远程 TXT 文件的 "频道名称,URL" 格式
                channel_name, url = line.split(",", 1)
                channel_name = channel_name.strip()
                url = url.strip()
                if url.startswith("http"):
                    # 检查是否在黑名单中
                    if is_url_blacklisted(url, url_blacklist):
                        print(f"跳过黑名单中的 URL: {url}")
                        continue
                    # 解析 IP 版本
                    ip_version = get_ip_version(url)
                    entry = f'#EXTINF:-1 group-title="{group_title}",{channel_name}\n{url}\n'
                    if ip_version == "ipv4" and url not in seen_urls_ipv4:
                        ipv4_lines.append(entry)
                        seen_urls_ipv4.add(url)
                    elif ip_version == "ipv6" and url not in seen_urls_ipv6:
                        ipv6_lines.append(entry)
                        seen_urls_ipv6.add(url)
                    elif ip_version is None:
                        # 如果无法解析 IP 版本，添加到 IPv4 文件（默认）
                        if url not in seen_urls_ipv4:
                            ipv4_lines.append(entry)
                            seen_urls_ipv4.add(url)
            elif line.startswith("http"):
                # 远程 M3U 文件的 URL 行
                url = line
                # 检查是否在黑名单中
                if is_url_blacklisted(url, url_blacklist):
                    print(f"跳过黑名单中的 URL: {url}")
                    continue
                # 解析 IP 版本
                ip_version = get_ip_version(url)
                if previous_line.startswith("#EXTINF"):
                    entry = f'{previous_line}\n{url}\n'
                else:
                    entry = f'#EXTINF:-1 group-title="{group_title}",Unknown Channel\n{url}\n'
                if ip_version == "ipv4" and url not in seen_urls_ipv4:
                    ipv4_lines.append(entry)
                    seen_urls_ipv4.add(url)
                elif ip_version == "ipv6" and url not in seen_urls_ipv6:
                    ipv6_lines.append(entry)
                    seen_urls_ipv6.add(url)
                elif ip_version is None:
                    # 如果无法解析 IP 版本，添加到 IPv4 文件（默认）
                    if url not in seen_urls_ipv4:
                        ipv4_lines.append(entry)
                        seen_urls_ipv4.add(url)
            previous_line = line

    # 保存到 IPv4 文件
    with open(output_ipv4_file, "w", encoding="utf-8") as f:
        f.writelines(ipv4_lines)

    # 保存到 IPv6 文件
    with open(output_ipv6_file, "w", encoding="utf-8") as f:
        f.writelines(ipv6_lines)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("用法: python merge_m3u.py <本地文件> <IPv4 输出文件> <IPv6 输出文件>")
        sys.exit(1)
    local_file = sys.argv[1]
    output_ipv4_file = sys.argv[2]
    output_ipv6_file = sys.argv[3]

    # 加载 config.py 中的远程直播源和黑名单
    remote_sources, url_blacklist = load_config("config.py")
    if not remote_sources:
        print("错误: config.py 中未找到 source_urls 变量")
        sys.exit(1)

    # 下载可用的远程直播源
    remote_files = download_remote_sources(remote_sources)

    # 合并直播源
    merge_m3u(local_file, remote_files, output_ipv4_file, output_ipv6_file, url_blacklist)
