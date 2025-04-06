# config.py

# 源 URL 列表：包含多个在线直播源的 URL
source_urls = [
    "your_first_remote_url_here",
    "your_second_remote_url_here",
    # 可以添加更多 URL
]

# EPG (Electronic Program Guide) URL 列表（可选）
epg_urls = [
    "your_epg_url_here",
    # 可以添加更多 EPG URL
]

# URL 黑名单：包含需要过滤的 URL 关键词
url_blacklist = [
    "some_unwanted_keyword",
    "another_unwanted_keyword",
    # 可以添加更多关键词
]

# IP 版本优先级： "ipv6" 或 "ipv4"
ip_version_priority = "ipv4"  # 设置默认优先级

# 公告信息（可选）：在生成的 M3U 和 TXT 文件开头添加公告
announcements = [
    {
        'channel': '公告',
        'entries': [
            {'name': '欢迎使用！', 'url': '#', 'logo': ''},
            {'name': '更多信息请访问...', 'url': 'your_website_here', 'logo': ''},
            # 可以添加更多公告条目
        ]
    },
    # 可以添加更多公告分组
]
