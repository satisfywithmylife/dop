import asyncio
import sys
import httpx
from loguru import logger
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_account.messages import defunct_hash_message
from functools import cached_property
import json
from web3.exceptions import TransactionNotFound
from config import *
from web3.eth import AsyncEth
import time
import random
from eth_abi import encode

g_success, g_fail = 0, 0

logger.remove()
logger.add('my.log', format='<g>{time:YYYY-MM-DD HH:mm:ss:SSS}</g> | <c>{level}</c> | <level>{message}</level>')
logger.add(sys.stdout, format='<g>{time:YYYY-MM-DD HH:mm:ss:SSS}</g> | <c>{level}</c> | <level>{message}</level>')

# https://doptest.dop.org?id=ZdbWvzM
class Dop:
    def __init__(self, pk, auth_token, referral='ZdbWvzM', proxy='', gas_scala=1.2):
        proxy = {
            'all://': f'{proxy}' if proxy else None
        }
        self.gas_scala = gas_scala
        self.http = httpx.AsyncClient(verify=False, proxies=proxy, timeout=120)
        self.Twitter = httpx.AsyncClient(verify=False, proxies=proxy, timeout=120)
        self.pk = pk
        self.account: Account = Account.from_key(pk)
        self.w3 = Web3(
            Web3.AsyncHTTPProvider(endpoint_uri='https://gateway.tenderly.co/public/sepolia'),
            modules={"eth": (AsyncEth,)}
        )
        self.exploer = 'https://sepolia.etherscan.io/tx/{}'
        self.proxy_str = proxy
        self.Twitter.headers = {
            'Accept-Language': 'en-US,en;q=0.8',
            'Authority': 'twitter.com',
            'Origin': 'https://twitter.com',
            'Referer': 'https://twitter.com/',
            'Sec-Ch-Ua': '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': "Windows",
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate, br',

        }
        self.dop_host = 'https://rewards-api.dop.org/{}'
        self.Twitter.cookies.update({'auth_token': auth_token})
        self.oauth_token, self.authenticity_token, self.oauth_verifier, self.token = None, None, None, None
        self.referral = referral
        self.u_info = {}
        
    def add_log(self, log_str, tx_hash=''):
        log_str = f'{self.account.address} ' + log_str
        if tx_hash and isinstance(tx_hash, str):
            log_str += f' | Tx {self.exploer.format(tx_hash)}'
        logger.debug(log_str)
        
    @cached_property
    def _get_sign(self):
        address = self.account.address.lower()
        sign_str = address + address + 'weareDOPdev'
        msghash = encode_defunct(text=sign_str)
        sign = Account.sign_message(msghash, self.pk)
       
        sign = str(sign.signature.hex())
        return sign
    
    async def get_geo_info(self):
        return {
            'location': 'United States'
        }
        
    async def get_ip(self):
        res = await self.http.get(url='https://ip.nf/me.json')
        res = res.json()
        return f"http://{res['ip']['ip']}/"
        
    async def create_account(self):
        url = self.dop_host.format('rewards')
        geo = await self.get_geo_info()
        payload = {
            "email": await self.get_mail(),
            "externalWalletAddress": self.account.address,
            "internalWalletAddress": self.account.address.lower(),
            "ip": await self.get_ip(),
            "location": geo['location'],
            "referalByCode": self.referral,
            "sign": self._get_sign
        }
        
        res = await self.http.post(url=url, json=payload)
        res = res.json()
        if res['statusCode'] == 201:
            return res['data']
        
        return False
    
    async def get_user_info(self):
        if self.u_info:
            return self.u_info
        url = self.dop_host.format('rewards/walletaddress')
        payload={
            'internalWalletAddress': self.account.address.lower(),
            'externalWalletAddress': self.account.address,
            'sign': self._get_sign
        }
        
        res = await self.http.get(url=url, params=payload)
        #{'statusCode': 200, 'data': {'updatedReward': {'claim_Sepolia': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'claim_Dop': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'claim_Testnet_Assets': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'encrypt_Assets': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'decrypt_Assets': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'send_Assets': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'follow_Us_On_Twitter': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, 'threeInvites': {'isCompleted': False, 'completedAt': '2024-02-24T19:24:46.103Z'}, '_id': '65da427e8d841d7134ffffcf', 'externalWalletAddress': '0x05b89d24074d6c5cf8dc75490da44663a20acba0', 'internalWalletAddress': '0x05b89d24074d6c5cf8dc75490da44663a20acba0', 'influencerId': {'_id': '65da427e8d841d7134ffffcd', 'referalByCode': 'ZdbWvzM', 'referalCode': 'F3sLV4H', 'email': '1075022284@qq.com', 'isActive': True, 'deleted': False}, 'referedId': '65d9cd968d841d7134e620f1', 'role': 'user', 'ip': 'http://104.28.240.133/', 'location': 'united states', 'referrals': 0, 'status': False, 'completionStatus': 0, 'overallCompletionPercentage': 0, 'createdAt': '2024-02-24T19:24:46.104Z', 'updatedAt': '2024-02-24T19:24:46.104Z', '__v': 0}, 'totalcount': 0, 'stepsCompletionCount': 0}}
        res = res.json()
        if res['statusCode'] == 404:
            self.add_log('账号不存在，开始创建账号')
            res = await self.create_account()
            if res:
                return await self.get_user_info()
        self.add_log(f'用户信息: {json.dumps(res)}')
        self.u_info = res['data']    
        return res['data']
    
    async def _get_id(self):
        u_info = await self.get_user_info()
        return u_info['updatedReward']['_id']
    

    async def get_twitter(self):
        try:
            response = await self.http.post(self.dop_host.format('rewards/auth/twitter/reverse'))
            response = response.json()
            if 'oauth_token' in response.keys():
                self.oauth_token = response['oauth_token']
                return True
            self.add_log(f'获取oauth_token失败')
            return False
        except Exception as e:
            self.add_log(f'获取oauth_token异常')
            return False


    async def get_twitter_token(self):
        
        if not await self.get_twitter():
            return False
        try:

            url = f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}'
            response = await self.Twitter.get(url)
            if 'authenticity_token' in response.text:
                self.authenticity_token = response.text.split('authenticity_token" value="')[1].split('"')[0]
                return True
            self.add_log(f'获取authenticity_token失败')
            return False
        except:
            self.add_log(f'获取authenticity_token异常')
            return False
        
        
    async def check_auth_twitter(self):
        if not await self.twitter_authorize():
            return False
        try:
            url = self.dop_host.format('rewards/auth/twitter')
            payload = {
                'oauth_verifier': self.oauth_verifier,
                'oauth_token': self.oauth_token
            }
            res = await self.http.post(url=url, data=payload)
            res = res.json()
            if res['statusCode'] == 200:
                self.add_log('推特认证通过')
                return True
            self.add_log(f'推特认证失败: {res["message"]}')
            return False
        except:
            self.add_log(f'推特认证异常')
            return False
        
    async def check_twitter_follow(self):
        if not await self.check_auth_twitter():
            return False
        _id = await self._get_id()
        url = self.dop_host.format(f'rewards/{_id}/toggle-twitter')
        payload = {
            'oauth_verifier': self.oauth_verifier,
            'oauth_token': self.oauth_token
        }
        res = await self.http.patch(url=url, params=payload)
        res = res.json()
        if res['statusCode'] == 200:
            return True
        return False

    async def twitter_authorize(self):
        if not await self.get_twitter_token():
            return False
        data = {
            'authenticity_token': self.authenticity_token,
            'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={self.oauth_token}',
            'oauth_token': self.oauth_token
        }
        response = await self.Twitter.post('https://api.twitter.com/oauth/authorize', data=data)
        if 'oauth_verifier' in response.text:
            self.oauth_verifier = response.text.split('oauth_verifier=')[1].split('"')[0]
            self.add_log(f'获取oauth_verifier: {self.oauth_verifier}')
            return True
        self.add_log(f'获取oauth_verifier失败')
        return False
       

    async def twitter_login(self):
        try:
            if not await self.twitter_authorize():
                return False
            response = await self.http.get(f'https://dropcoin.online/auth/twitter?oauth_token={self.oauth_token}&oauth_verifier={self.oauth_verifier}')
            if 'token' in response.text:
                self.token = response.json()['token']
                self.http.headers.update({'Authorization': f'Token {self.token}'})
                return True
            self.add_log(f'twitter登录失败')
            return False
        except Exception as e:
            self.add_log(f'{e}, 4444')
            return False
        
        
    async def claim_sepolia(self):
        url = self.dop_host.format('rewards/getSepolia')
        payload = {
            'internalWalletAddress': self.account.address.lower(),
            'externalWalletAddress': self.account.address,
            'sign':self._get_sign
        }
        res = await self.http.get(url=url, params=payload, timeout=60)
        res = res.json()
        if res['statusCode'] != 200:
            self.add_log(f'领水错误：{res["message"]}')
            return False
        self.add_log('领sepolia水成功！')
        return True
        
    def load_abi(self, abi_name):
        with open(f'./abi/{abi_name}.json', 'r') as f:
            json_data = json.load(f)
            return json_data
        
    async def approve(self, token_contract, spender, amount):
        allowance = await token_contract.functions.allowance(self.account.address, spender).call()
        if allowance >= amount:
            return True
        tx_data = await self.get_tx_data()
        approve_tx = await token_contract.functions.approve(
            spender,
            amount
        ).build_transaction(tx_data)
        approve_tx_hash = await self._make_tx(tx=approve_tx)
        return True
        
    async def get_tx_data(self, eth_amount=0, gas_price=0, is_eip1559=False):
        net_price = await self.w3.eth.gas_price
        tx = {
            "chainId": await self.w3.eth.chain_id,
            "from": self.account.address,
            "value": eth_amount,
            "nonce": await self.w3.eth.get_transaction_count(self.account.address),
        }
        if is_eip1559:
            tx.update({'maxFeePerGas': gas_price if gas_price else int(self.gas_scala * net_price)})
            tx.update({'maxPriorityFeePerGas': gas_price if gas_price else int(self.gas_scala * net_price)})
        else:
            tx.update({"gasPrice": gas_price if gas_price else int(net_price * self.gas_scala)})
        return tx
        
    async def get_fee(self, tx, gas=0):
        net_fee = await self.w3.eth.estimate_gas(tx)
        tx.update({
            'gas': gas if gas else net_fee
        })
        signed_txn = self.account.sign_transaction(tx)
        return signed_txn
    
    async def send_tx(self, signed_txn):
        order_hash = await self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        return order_hash
        
    async def _make_tx(self, tx, gas=0):
        
        signed_txn = await self.get_fee(tx, gas)
        order_hash = await self.send_tx(signed_txn)
        await self.wait_until_tx_finished(order_hash.hex())
        return order_hash.hex()
    
    async def wait_until_tx_finished(self, hash: str, max_wait_time=180):
        start_time = time.time()
        while True:
            try:
                receipts = await self.w3.eth.get_transaction_receipt(hash)
                status = receipts.get("status")
                if status == 1:
                    return True
                elif status is None:
                    await asyncio.sleep(0.3)
                else:
                    logger.error(f"[{self.account_id}][{self.address}] {self.explorer}{hash} transaction failed!")
                    return False
            except TransactionNotFound:
                if time.time() - start_time > max_wait_time:
                    self.add_log(f'FAILED TX: {hash}')
                    return False
                await asyncio.sleep(1)
                
    async def claim_dop(self):
        contract = self.w3.eth.contract(address=dop, abi=self.load_abi('dop'))
        tx_data = await self.get_tx_data()
        tx = await contract.functions.mint(Web3.to_wei(1000, 'ether')).build_transaction(tx_data)
        tx_hash = await self._make_tx(tx=tx)
        if await self.update_rewards('claim_Dop'):
            self.add_log('claim dop 成功', tx_hash)
            return True
            
        return False
    
    async def claim_testnet_assets(self):
        contract = self.w3.eth.contract(address=mintAll, abi=self.load_abi('mintAll'))
        tx_data = await self.get_tx_data()
        tx = await contract.functions.mintTokens(self.account.address).build_transaction(tx_data)
        tx_hash = await self._make_tx(tx=tx)
        
        if await self.update_rewards('claim_Testnet_Assets'):
            self.add_log('claim testnet assets 成功', tx_hash)
            return True
            
        return False
    
    def encrypt_sign(self, amount):
        ts = int(time.time()*1000)
        random_int = random.randint(100000, 999999)
        sign_list = [str(self.account.address), str(self.account.address), int(amount), random_int, ts]
        keck_msg = self.w3.solidity_keccak(['address', 'address', 'uint256', 'uint256', 'uint256'], sign_list)
        h = defunct_hash_message(hexstr=keck_msg.hex())
        signed_message = self.account.signHash(h)
        r_int, s_int, v = signed_message.r, signed_message.s, signed_message.v
        r, s = int.to_bytes(r_int, 32, 'big'), int.to_bytes(s_int, 32, 'big')
        r, s =  r.hex(), s.hex()
        return r,s,v,ts,random_int
        
    
    async def encrypt_assets(self, coin_address=usdt):
        token_contract = self.w3.eth.contract(address=coin_address, abi=self.load_abi('erc20'))
        # amount = int(random.randint(100, 200) * 1e6)
        amount = await token_contract.functions.balanceOf(self.account.address).call()
        approve_res = await self.approve(token_contract, tpl, amount)
        r,s,v,ts,random_int = self.encrypt_sign(amount)
        if approve_res:
            method_id = '0x79df7682'
            args = [
                self.account.address,
                random_int,
                ts,
                amount,
                21,
                v,
                Web3.to_bytes(hexstr=r),
                Web3.to_bytes(hexstr=s),
            ]
            tx_data = await self.get_tx_data()
            txn_data = method_id + encode(types=["address","uint256","uint256","uint256","uint256","uint256","bytes32","bytes32"], args=args).hex()

            tx_data.update({
                'data': txn_data,
                'to': tpl
            })
            # print(tx_data)
            tx_hash = await self._make_tx(tx=tx_data)
            if tx_hash:
                if await self.update_rewards('encrypt_Assets'):
                    self.add_log('encrypt assets 成功', tx_hash)
                    return True
                
            return False
            
    async def send_assets(self, coin_address=dop):
        token_contract = self.w3.eth.contract(address=coin_address, abi=self.load_abi('erc20'))
        # balance = await token_contract.functions.balanceOf(self.account.address).call()
        # print(balance)
        amount = int(random.randint(1, 3) * 1e4)
        balance = await token_contract.functions.balanceOf(self.account.address).call()
        approve_res = await self.approve(token_contract, tpl, balance)
        r,s,v,ts,random_int = self.encrypt_sign(amount)
        if approve_res:
            method_id = '0xe54a9a7c'
            args = [
                self.account.address,
                dop_account,
                amount,
                random_int,
                ts,
                21,
                v,
                Web3.to_bytes(hexstr=r),
                Web3.to_bytes(hexstr=s),
            ]
            tx_data = await self.get_tx_data()
            txn_data = method_id + encode(types=["address","address","uint256","uint256","uint256","uint256","uint256","bytes32","bytes32"], args=args).hex()

            tx_data.update({
                'data': txn_data,
                'to': tpl
            })
            tx_hash = await self._make_tx(tx=tx_data, gas=200000)
            if tx_hash:
                if await self.update_rewards('send_Assets'):
                    self.add_log('send assets 成功', tx_hash)
                    return True
            
            return False
            
    
    async def decrypt_assets(self, coin_address=usdt):
        token_contract = self.w3.eth.contract(address=coin_address, abi=self.load_abi('erc20'))
        amount = int(random.randint(3, 7) * 1e6)
        approve_res = await self.approve(token_contract, tpl, amount)
        r,s,v,ts,random_int = self.encrypt_sign(amount)
        if approve_res:
            method_id = '0x676df6b3'
            args = [
                self.account.address,
                self.account.address,
                amount,
                random_int,
                ts,
                21,
                v,
                Web3.to_bytes(hexstr=r),
                Web3.to_bytes(hexstr=s),
            ]
            tx_data = await self.get_tx_data()
            txn_data = method_id + encode(types=["address","address","uint256","uint256","uint256","uint256","uint256","bytes32","bytes32"], args=args).hex()

            tx_data.update({
                'data': txn_data,
                'to': tpl
            })
            # print(tx_data)
            
            tx_hash = await self._make_tx(tx=tx_data)
            if tx_hash:
                if await self.update_rewards('decrypt_Assets'):
                    self.add_log('decrypt assets 成功', tx_hash)
                    return True
            
            return False
        
    # 刷新奖励
    async def update_rewards(self, task_name):
        _id = await self._get_id()
        url = self.dop_host.format(f'rewards/{_id}')
        payload = {
            'internalWalletAddress': self.account.address.lower(),
            'externalWalletAddress': self.account.address,
            'sign':self._get_sign,
            task_name: {
                'isCompleted': True
            }
        }
        res = await self.http.patch(url=url, json=payload, timeout=60)
        res = res.json()
        if res['statusCode'] == 200:
            return True
        
        return False
                
    async def get_my_code(self):
        u_info = await self.get_user_info()
        return u_info['updatedReward']['influencerId']['referalCode']
    
    async def get_my_email(self):
        u_info = await self.get_user_info()
        return u_info['updatedReward']['influencerId']['email']
    
    async def check_my_referor(self):
        u_info = await self.get_user_info()
        return u_info['updatedReward']['influencerId']['referalByCode']
    
    async def three_invites(self):
        pass
        
    async def make_task(self):
        u_info = await self.get_user_info()
        task_list = [
            ['follow_Us_On_Twitter', self.check_twitter_follow],
            ['claim_Sepolia', self.claim_sepolia, 1],
            ['claim_Dop', self.claim_dop],
            ['claim_Testnet_Assets', self.claim_testnet_assets],
            ['encrypt_Assets', self.encrypt_assets],
            ['send_Assets', self.send_assets],
            ['decrypt_Assets', self.decrypt_assets],
            ['threeInvites', None]
        ]
        for task_config in task_list:
            if not u_info['updatedReward'][task_config[0]]['isCompleted'] and task_config[1]:
                if not await task_config[1]():
                    
                    return False, task_config[0]
                elif len(task_config) == 3:
                    check_times = 50
                    while check_times:
                        balance = await self.w3.eth.get_balance(self.account.address)
                        if not balance:
                            await asyncio.sleep(1)
                            check_times -= 1
                        else:
                            self.add_log('领水已到账')
                            break
                    if not check_times:
                        self.add_log('水一直未到账，跳过')
                        return False, task_config[0]
        
        return True, task_config[0]
     
          
    async def get_mail(self):
        while 1:
            try:
                res = await self.http.get(f'https://www.1secmail.com/api/v1/?action=genRandomMailbox')
                if '@' in res.text:
                    return res.json()[0]
            except:
                print('获取email失败')
                pass

async def main(file_name, code, loop_invite):
    global g_fail, g_success
    jump = 1
    with open(file_name, 'r', encoding='UTF-8') as f, open('success.txt', 'a') as s, open('error.txt', 'a') as e, open('my.txt', 'a') as z:  # eth----auth_token
        lines = f.readlines()
        for twitter in lines:
            _auth_tokn = ''
            t_list = twitter.split('----')
            for tw in t_list:
                if len(tw) == 40 and all(c in '0123456789abcdef' for c in tw):
                    _auth_tokn = tw
                    break
            if not _auth_tokn:
                continue
            pk = t_list[1]
            
            _nstproxy = ''
            if not nstproxy_Channel or not nstproxy_Password:
                logger.error('请配置 nstproxy 代理信息')
                return
            _nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_BsqLCLkiVu:{nstproxy_Password}@gw-us.nstproxy.com:24125"
            # _res = httpx.get('https://ip.useragentinfo.com/json', proxies={'all://': _nstproxy})
            # print(_res.text)
            dop = Dop(pk=pk, referral=code, auth_token=_auth_tokn, proxy=_nstproxy)
            # if jump and dop.account.address != '0xC08063DB5bC08CeD3084542279aD95aE22e5C8E0':
            #     continue
            jump = 0
            try:
                my_code = await dop.get_my_code()
                email = await dop.get_my_email()
                if loop_invite:
                    code = my_code
                log_str = f'{dop.account.address}----{pk}----{email}----{tw}----{my_code}\n'
                res, k = await dop.make_task()
                
                if res:
                    dop.add_log(f'任务1-7完成成功')
                    s.write(log_str)
                else:
                    dop.add_log(f'任务{k}失败')
                    e.write(log_str)
            except Exception as m:
                print(f'{m}')

if __name__ == '__main__':
    _referral = 'ZdbWvzM' # 大号邀请码
    _file_name = 'tw_bind.txt' # 执行make.py重新生成的文件
    _loop_invite = True # 默认滚动邀请，一个号跑完任务，无论是否一次成功，自动变成邀请人，邀请下一个号做任务，False则只用大号邀请码作为邀请人
    asyncio.run(main(_file_name, _referral, _loop_invite))
