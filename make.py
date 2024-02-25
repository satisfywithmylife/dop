from web3 import Web3
from eth_account import Account

def make():
    with open('tw.txt', 'r') as f:
        for row in f.readlines():
            row = row.strip()
            pk = Account.create().key.hex()
            ac = Account.from_key(pk)
            ac_str = f'{ac.address}----{pk}----{row}\n'
            with open('tw_bind.txt', 'a+') as z:
                z.write(ac_str)

if __name__ == '__main__':
    ''''
    给购买的推特账号配对随机以太坊钱包账号
    格式：地址----私钥----购买的推特的某行数据
    保存到tw_bind.txt文件夹中
    '''
    make()