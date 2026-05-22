import json
import csv
import os
import urllib.parse
import copy
from paramiko import SSHClient, AutoAddPolicy, Ed25519Key, SSHException
from time import sleep
from hashlib import sha256

SERVERS_CSV = "./singbox服务器信息.csv"
USERS_CSV = "./singbox客户uuid.csv"
SERVER_TEMPLATE_FILE = "./template/1.12+模板.txt"

SERVERS_DIR = "./服务器配置/输出文件夹"
CLIENTS_OUT_DIR = "./客户端链接/输出文件夹"

def load_csv(file_path):
    """读取 CSV 文件并过滤空行，支持中英文表头"""
    data = []
    if not os.path.exists(file_path):
        print(f"❌ 找不到文件: {file_path}")
        return data
    with open(file_path, mode='r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        # 统一表头为小写
        reader.fieldnames = [str(name).strip().lower() for name in reader.fieldnames if name]
        for row in reader:
            # 过滤掉空格和 None，提取有效键值对
            clean_row = {k: v.strip() for k, v in row.items() if k and v and v.strip()}
            # 只有当这行有真实数据时，才加入到列表中（完美解决空行产生的 {} 问题）
            if clean_row:
                data.append(clean_row)
    return data

#自动SSH登录模块
class auto_deployer():
    def __init__(self, host_ip, username, key_path, key_pswd):
        self.host = host_ip
        self.username = username
        self.client = self._get_client(key_path, key_pswd)
        self.shell = self.client.invoke_shell()
        sleep(2)
        if self.shell.recv_ready():
            self.shell.recv(9999)
            
    def _get_client(self, key_path, key_pswd):
        # 强制只使用密钥登录，去除了密码回退逻辑
        # 出于安全考虑，强烈不建议使用密码登录，密钥尽量使用ED25519密钥
        ssh_key = Ed25519Key.from_private_key_file(filename=key_path, password=key_pswd)
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy)
        client.connect(self.host, username=self.username, pkey=ssh_key)
        return client

    def send_command(self, command):
        self.shell.send("{}\n".format(command))
        sleep(0.75) # 给予命令执行时间
        if self.shell.recv_ready():
            return self.shell.recv(9999).decode('utf-8', errors='ignore')
        return ""

    def upload_and_restart(self, local_config_path):
        # 1. SFTP 上传文件
        sftp = self.client.open_sftp()
        sftp.put(local_config_path, "/路径/服务端配置.json") 
        sftp.close()
        print("    [+] 配置文件已成功上传")
        
        # 2. 强制终止现有进程并运行新配置
        # 注意：此处加上 nohup 和 & 让其在后台运行，否则直接 run 会导致 SSH 进程阻塞卡死
        # 如果sing-box为服务，则将self.send_command里面内容替换为“sudo systemctl restart sing-box.service” （此处假设sing-box服务名称为sing-box.service）
        self.send_command("sudo pkill -9 sing-box ; nohup sudo sing-box run -c /路径/服务器配置文件.json > /dev/null 2>&1 &")
        print("    [+] 已执行: 终止旧进程并后台启动新配置")
        
    def close_ssh_session(self):
        self.client.close()

def process_server_configs(servers, users, template_path):
    """智能同步服务端配置：检测 UUID 匹配及元数据变更"""
    os.makedirs(SERVERS_DIR, exist_ok=True)
    
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            base_template = json.load(f)
    except Exception as e:
        print(f"❌ 读取服务端模板失败: {e}")
        return

    # 准备表格中最新的用户列表（用于更新）
    new_user_list = [{"name": u["user name"], "uuid": u["uuid"]} for u in users]
    # 用于检测的 UUID 集合
    new_uuids_set = set(u["uuid"] for u in new_user_list)

    #出于安全考虑，强烈建议使用密码保护SSH密钥
    key_pswd_correctness = False
    key_pswd = input("请输入ssh密钥密码:")
    #出于安全原因，强烈不建议通过明文对比密码正确性
    #使用错误密码继续但是跳过自动远程部署
    key_hash = sha256(key_pswd.encode('utf-8')).hexdigest()
    correct_hash = "正确密码的哈希值"
    if key_hash == correct_hash:
        key_pswd_correctness = True
    else:
        print("\n⚠️密钥密码错误，将跳过自动远程部署")

    for server in servers:
        # 获取最新的表头字段：服务器配置文件名称
        server_name = server.get('server conf')
        if not server_name: continue
            
        file_name = f"{server_name}.json"
        config_path = os.path.join(SERVERS_DIR, file_name)
        
        # 表格中的最新元数据 (注意区分 SNI 和 配置文件名称)
        target_sni = server.get('sni')
        target_priv_key = server.get('reality priv key')
        target_short_id = server.get('short id')

        needs_save = False
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print(f"🔍 检测现有服务器配置: {server_name}")
        else:
            config = copy.deepcopy(base_template)
            needs_save = True
            print(f"✨ 发现新服务器，创建配置: {server_name}")

        # 遍历 inbound 节点进行同步
        for inbound in config.get('inbounds', []):
            if inbound.get('type') == 'vless':
                
                # 1. 检测 UUID 列表
                current_uuids = set(u.get('uuid') for u in inbound.get('users', []))
                if current_uuids != new_uuids_set:
                    inbound['users'] = new_user_list
                    needs_save = True
                    print(f"  [-] 用户 UUID 列表变更，已同步最新的用户名和 UUID。")

                # 2. 检测元数据更新 (私钥, SNI, ShortID 等)
                if 'tls' in inbound and 'reality' in inbound['tls']:
                    tls_config = inbound['tls']
                    reality_config = tls_config['reality']
                    
                    if tls_config.get('server_name') != target_sni:
                        tls_config['server_name'] = target_sni
                        needs_save = True
                    if reality_config.get('private_key') != target_priv_key:
                        reality_config['private_key'] = target_priv_key
                        needs_save = True
                    if reality_config.get('short_id') != [target_short_id]:
                        reality_config['short_id'] = [target_short_id]
                        needs_save = True
                    if reality_config.get('handshake', {}).get('server') != target_sni:
                        reality_config['handshake']['server'] = target_sni
                        needs_save = True
                break
        
        if needs_save:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"  ✅ {server_name}配置已同步更新。")
            # ================= 增加的 SSH 自动部署逻辑 =================
            server_mgmt = server.get('mgmt addr') # 读取表格中的管理地址
            if server_mgmt and key_pswd_correctness:
                try:
                    print(f"  🚀 正在通过 [{server_mgmt}] 自动部署...")
                    
                    # 请根据你的实际情况修改 username 和 key_path
                    deployer = auto_deployer(
                        host_ip=server_mgmt, 
                        username="用户名", 
                        key_path="SSH密钥/路径", 
                        key_pswd=key_pswd # 如果你的私钥有密码，请在这里填入
                    )
                        
                    deployer.upload_and_restart(local_config_path=config_path)
                    deployer.close_ssh_session()
                    print(f"   🎉{server_name}远程部署完成！")                     
                except Exception as e:
                    print(f"   ❌{server_name}远程部署失败: {e}")
            else:
                if not server_mgmt:
                    print(f"   ⚠️ 表格中未提供{server_name}的管理地址，已跳过远程部署。")
            # ==========================================================
        else:
            print(f"  ⚡{server_name}配置内容与表格一致，无需改动。")
            
def generate_client_links(servers, users):
    """为每个用户分别生成包含 IPv4 和 IPv6 节点链接的 txt 文件"""
    os.makedirs(CLIENTS_OUT_DIR, exist_ok=True)

    for user_idx, user in enumerate(users):
        user_name = user.get('user name') or user.get('name')
        user_uuid = user.get('uuid')
        if not user_name or not user_uuid: continue

        ipv4_links = []
        ipv6_links = []

        for server in servers:
            # 严格提取你表格里的字段
            s_name = server.get('server conf')
            ipv4 = server.get('ip')
            ipv6 = server.get('ipv6')  # 提取表格中的 IPv6 列
            port = server.get('port') or '443'
            pbk = server.get('reality pub key')
            sni = server.get('sni')
            sid = server.get('short id')

            # 基础信息检查 (放宽 IP 检查，只要有 ipv4 或 ipv6 任意一个即可)
            if not all([pbk, sni, sid]) or (not ipv4 and not ipv6):
                if user_idx == 0:
                    missing=[]
                    if not ipv4: missing.append("IPv4地址")
                    if not ipv6: missing.append("ipv6地址")
                    if not pbk: missing.append("reality pub key")
                    if not sni: missing.append("SNI")
                    if not sid: missing.append("Short id")
                    print(f"⚠️ 警告: 节点 [{s_name}] 被跳过，表格缺少必填项: {missing}")
                continue

            remark_v4 = urllib.parse.quote(f"{s_name}_IPv4")
            remark_v6 = urllib.parse.quote(f"{s_name}_IPv6") # 给 IPv6 链接加个后缀以作区分

            # 生成 IPv4 链接
            if ipv4:
                link_v4 = (
                    f"vless://{user_uuid}@{ipv4}:{port}"
                    f"?security=reality&encryption=none&pbk={pbk}"
                    f"&headerType=none&fp=chrome&type=tcp&sni={sni}"
                    f"&sid={sid}#{remark_v4}"
                )
                ipv4_links.append(link_v4)

            # 生成 IPv6 链接
            if ipv6:
                # 去除表格里可能自带的方括号，防止重复嵌套变成 [[ip]]
                clean_ipv6 = ipv6.strip('[]')
                link_v6 = (
                    f"vless://{user_uuid}@[{clean_ipv6}]:{port}"
                    f"?security=reality&encryption=none&pbk={pbk}"
                    f"&headerType=none&fp=chrome&type=tcp&sni={sni}"
                    f"&sid={sid}#{remark_v6}"
                )
                ipv6_links.append(link_v6)

        # 写入 IPv4 链接文件
        if ipv4_links:
            output_v4 = os.path.join(CLIENTS_OUT_DIR, f"{user_name}.txt")
            with open(output_v4, 'w', encoding='utf-8') as f:
                f.write("\n\n".join(ipv4_links) + "\n\n")
            print(f"🔗 IPv4 链接已存入: {output_v4}")

        # 写入 IPv6 链接文件
        if ipv6_links:
            output_v6 = os.path.join(CLIENTS_OUT_DIR, f"ipv6/{user_name}_ipv6.txt")
            with open(output_v6, 'w', encoding='utf-8') as f:
                f.write("\n\n".join(ipv6_links) + "\n\n")
            print(f"🔗 IPv6 链接已存入: {output_v6}")

        if not ipv4_links and not ipv6_links:
            print(f"  [!] 用户 {user_name} 的链接未生成，无可用节点！")

            
if __name__ == "__main__":
    print("="*45)
    print("🚀 Sing-box 自动化同步管理系统")
    print("="*45)
    
    # 加载数据
    servers_data = load_csv(SERVERS_CSV)
    users_data = load_csv(USERS_CSV)
    try:
        if servers_data and users_data:
            # 处理服务端
            process_server_configs(servers_data, users_data, SERVER_TEMPLATE_FILE)
            print("-" * 45)
            # 处理客户端链接
            generate_client_links(servers_data, users_data)
            
            print("\n🎉 所有配置与链接已同步完成！")
    except(KeyboardInterrupt):
        print("终止")
