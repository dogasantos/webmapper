webmapper is designed to take a nmap xml report, parse and produce a line-by-line report with all web targets.

```
http://host:80/
https://host:443/
https://host:8443/
...
```

In case you have a massdns report file, this can be used to resolve all vhosts as well.

Example:

```
# webmapper -n report.nmap.xml -o output.web
webmapper 1.0 @ dogasantos
-------------------------------------------------------
parse nmap xml report and get all web services running
-------------------------------------------------------
  + Nmap report successfully loaded
  + Parsing target: 222.222.222.222
  + Parsing target: 222.222.222.223
  + Parsing target: 222.222.222.224
  + Parsing target: 222.222.222.225
  + Saving report: output.web
[*] Done.
# 

```

```
webmapper -n report.nmap.xml -o output.web -m report.massdns
webmapper 1.0 @ dogasantos
-------------------------------------------------------
parse nmap xml report and get all web services running
-------------------------------------------------------
  + Nmap report successfully loaded
  + Parsing target: 222.222.222.222
    + Found hostname: www1.hosttestexample.com
  + Parsing target: 222.222.222.223
    + Found hostname: www2.hosttestexample.com
  + Parsing target: 222.222.222.224
    + Found hostname: www3.hosttestexample.com
  + Parsing target: 222.222.222.225
    + Found hostname: www4.hosttestexample.com
  + Saving report: output.web
[*] Done.

```