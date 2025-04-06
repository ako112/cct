# config.py

# 源 URL 列表：包含多个在线直播源的 URL
source_urls = [   
"http://209.141.54.128:50007/?type=txt",
"https://web.banye.tech:7777/tvbus/yogurtTv.txt",
"https://live.zhoujie218.top/tv/iptv4.txt",
"https://raw.githubusercontent.com/ssili126/tv/main/itvlist.txt",
"https://live.zbds.top/tv/iptv4.txt",
"https://raw.githubusercontent.com/ssili126/tv/main/itvlist.m3u",
"https://raw.githubusercontent.com/fanmingming/live/refs/heads/main/tv/m3u/ipv6.m3u",
"https://aktv.space/live.m3u",
"https://raw.githubusercontent.com/Supprise0901/TVBox_live/main/live.txt",
"https://m3u.dxjc.pp.ua/proxy/tv3.m3u",
"https://ehe.serv00.net/tv3.m3u",
    # 可以添加更多 URL
]

# EPG (Electronic Program Guide) URL 列表（可选）
epg_urls = [
    "your_epg_url_here",
    # 可以添加更多 EPG URL
]

# URL 黑名单：包含需要过滤的 URL 关键词
url_blacklist = [
    "cdn.iptv8k.top",
"tv.nezha.su:35455",
    # 可以添加更多关键词
]

# IP 版本优先级： "ipv6" 或 "ipv4"
ip_version_priority = "ipv4"  # 设置默认优先级


