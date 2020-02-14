# DDoS Mitigation

Real-time detection of DDoS flood attacks. Automatically add BGP 
remote triggered black hole (RTBH) and FlowSpec to mitigate attack.

[Remotely Triggered Black Hole (RTBH) Routing](https://blog.sflow.com/2017/06/remotely-triggered-black-hole-rtbh.html)

[Real-time DDoS mitigation using sFlow and BGP FlowSpec](https://blog.sflow.com/2017/07/real-time-ddos-mitigation-using-sflow.html)

## To install

1. [Download sFlow-RT](https://sflow-rt.com/download.php)
2. Run command: `./sflow-rt/get-app.sh sflow-rt ddos-protect`
3. Restart sFlow-RT

Alternatively, use the Docker image:
https://hub.docker.com/r/sflow/ddos-protect/

Online help is available through web UI.

For more information, visit:
https://sFlow-RT.com
