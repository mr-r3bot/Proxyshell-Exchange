# Proxyshell-Exchange

Full write-up will be published here: https://mr-r3bot.github.io/researches/2021/08/16/My-journey-to-reproduce-Proxyshell-(reported-by-Orange-Tsai).html

- Poc script for ProxyShell exploit chain in Exchange Server
- Status: Finished

Looking for the right way to encode payload in python ...

------------
Usage

```
python proxyshell.py -u https://<exchange_server> -e <email> -p <local_wsman_port>

...
PS> get_shell
```
