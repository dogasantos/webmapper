webmapper is designed to take a nmap xml report, parse and produce a line-by-line report with all web targets as the example:


```
http://host:80/
https://host:443/
https://host:8443/
...
```
This report file adds a .web extension by itself. So a good example on how to use it should be:

```
