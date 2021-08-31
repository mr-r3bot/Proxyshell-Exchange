# Proxyshell-Exchange

Full write-up will be published here: https://mr-r3bot.github.io/research/2021/08/16/My-journey-to-reproduce-Proxyshell-(reported-by-Orange-Tsai).html

- Poc script for ProxyShell exploit chain in Exchange Server
- Status: Finished

Modify your own payload in `encode_payload.py` file
------------
Usage

```
python proxyshell.py -u https://<exchange_server> -e <email> -p <local_wsman_port>

...
PS> get_shell
```
