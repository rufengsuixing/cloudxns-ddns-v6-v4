# cloudxns-ddns-v6-v4
<h3>change your ddns with name not ids<br>
choose you internal or external ip<br>
can use Regular expression</h3>
<p>usage:
usage for internal ipv4 and for ipv6<br>
<code>ddnsxns.py --apik [key] --seck [key] --r4f [record4withdomain] --re4 [Regular expression to choose ipv4] --do [domain name] --r6 [record6] --re6 [Regular expression to choose ipv6] --otherpcname [the name of other pc if ddns for other] [--proxy_type sock s5] [--proxy_addr 127.0.0.1:1080] </code><br>
Regular expression examples: <br><code>10\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*</code><br><code>200[0-9]:.*:.*:.*:.*:.*"</code><br>
usage for external ipv4 and for ipv6 <br>
<code>ddnsxns.py --apik [key] --seck [key] --r4f [record4withdomain] --do [domain name] --r6 [record6] --re6 [Regular expression to choose ipv6] --otherpcname [the name of other pc if ddns for other] [--proxy_type socks5] [--proxy_addr 127.0.0.1:1080]</code><br>
if miss v4/v6 args will not change v4/v6 dns
</p>
