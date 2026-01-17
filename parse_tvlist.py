import tvlist_pb2
import urllib.request

# 从网络读取数据
url = "https://capi.yangshipin.cn/api/oms/pc/page/PG00000004"
req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    data = resp.read()

# 解析Response
response = tvlist_pb2.Response()
response.ParseFromString(data)

# 分类频道
yangshi_channels = []
yangshi_vip_channels = []
weishi_channels = []

for channel in response.data.content.list:
    pay_type = ""
    if channel.pay_info.HasField('detail'):
        pay_type = channel.pay_info.detail.pay_type

    if channel.source == "yangshi":
        if pay_type == "30002":  # VIP
            yangshi_vip_channels.append(channel)
        else:
            yangshi_channels.append(channel)
    elif channel.source == "weishi":
        weishi_channels.append(channel)

# 生成URL
def gen_url(ch):
    return f"http://127.0.0.1:8080/ysp?cnlid={ch.cnlid}&livepid={ch.livepid}&defn=fhd"

# 输出结果
with open('tvlist.txt', 'w', encoding='utf-8') as out:
    # 央视
    out.write("央视,#genre#\n")
    for ch in yangshi_channels:
        out.write(f"{ch.name},{gen_url(ch)}\n")

    out.write("\n")

    # 央视VIP
    out.write("央视VIP,#genre#\n")
    for ch in yangshi_vip_channels:
        out.write(f"{ch.name},{gen_url(ch)}\n")

    out.write("\n")

    # 卫视
    out.write("卫视,#genre#\n")
    for ch in weishi_channels:
        out.write(f"{ch.name},{gen_url(ch)}\n")

print("生成完成，结果已保存到 tvlist.txt")
