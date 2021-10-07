# DDoS Mitigation

Real-time detection of DDoS flood attacks. Automatically add BGP 
remote triggered black hole (RTBH) and FlowSpec to mitigate attack.

[DDoS protection quickstart guide](https://blog.sflow.com/2021/10/ddos-protection-quickstart-guide.html)

## To install

1. [Download sFlow-RT](https://sflow-rt.com/download.php)
2. Run command: `./sflow-rt/get-app.sh sflow-rt ddos-protect`
3. Optionally, run command: `./sflow-rt/get-app.sh sflow-rt browse-flows`
4. Restart sFlow-RT

Alternatively, use the Docker image:
https://hub.docker.com/r/sflow/ddos-protect/

Online help is available through web UI.

For more information, visit:
https://sFlow-RT.com
