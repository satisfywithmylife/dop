<h1 align="center">DopTestnet</h1>

<p align="center">测试网任务<a href="https://doptest.dop.org?id=ZdbWvzM">Testnet</a></p>
<p align="center">
<img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54">
</p>

## ⚡ 安装
+ 安装 [python](https://www.google.com/search?client=opera&q=how+install+python)
+ [下载项目](https://sites.northwestern.edu/researchcomputing/resources/downloading-from-github) 并解压
+ 安装依赖包:
```python
pip install -r requirements.txt
```

## 💻 准备
+ [nstproxy国外住宅代理购买](https://app.nstproxy.com/register?i=EM00Pe)
+ [推特账号购买](https://hdd.cm) [@fooyao](https://twitter.com/fooyao)

**充值后，创建频道，复制频道名和密码，分别写入config.py的```nstproxy_Channel```,```nstproxy_Password```中**

**购买后的推特账号，放在项目的tw.txt文件内**

```
首次执行 python make.py, 仅需执行一次
跑任务 python main.py 自动检测哪些任务已完成，完成的会跳过，可重复执行
```
```python
# main.py 部分说明
async def main(file_name, code, loop_invite):
    global g_fail, g_success
    with open(file_name, 'r', encoding='UTF-8') as f, open('dropcoin_success.txt', 'a') as s, open('dropcoin_error.txt', 'a') as e, open('my.txt', 'a') as z:  # eth----auth_token
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
            mail = await get_mail()
            
            _nstproxy = ''

            _nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_BsqLCLkiVu:{nstproxy_Password}@gw-us.nstproxy.com:24125"
            # _res = httpx.get('https://ip.useragentinfo.com/json', proxies={'all://': _nstproxy})
            # print(_res.text)
            dop = Dop(email=mail, pk=pk, referral=code, auth_token=_auth_tokn, proxy=_nstproxy)
            
            try:
                my_code = await dop.get_my_code()
                if loop_invite:
                    code = my_code
                log_str = f'{dop.account.address}----{pk}----{mail}----{tw}----{my_code}\n'
                res, k = await dop.make_task()
                
                if res:
                    dop.add_log(f'任务1-7完成成功')
                    s.write(log_str)
                else:
                    dop.add_log(f'任务{k}失败')
                    e.write(log_str)
            except:
                z.write(log_str)

if __name__ == '__main__':
    _referral = 'ZdbWvzM' # 大号邀请码
    _file_name = 'tw_bind.txt' # 执行make.py重新生成的文件
    _loop_invite = True # 默认滚动邀请，一个号跑完任务，无论是否一次成功，自动变成邀请人，邀请下一个号做任务，False则只用大号邀请码作为邀请人
    
    asyncio.run(main(_file_name, _referral, _loop_invite))
```

## 其他  ✔️ 
**推特绑定接口经常出错，可能是账号或者代理问题**

## 📧 Contacts
+ 推特 - [@shawngmy](https://twitter.com/shawngmy)
+ tks for following，if u want get more info
