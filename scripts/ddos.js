// author: InMon
// version: 2.0
// date: 4/6/2020
// description: Use BGP to mitigate DDoS flood attacks
// copyright: Copyright (c) 2015-2020 InMon Corp.

include(scriptdir()+'/inc/trend.js');

var router = getSystemProperty("ddos_protect.router") || '127.0.0.1';
var my_as = getSystemProperty("ddos_protect.as") || '65000';
var my_id = getSystemProperty("ddos_protect.id") || '0.6.6.6';
var community = getSystemProperty("ddos_protect.community") || '65535:666'; // RFC7999
var nexthop = getSystemProperty("ddos_protect.nexthop") || '192.0.2.1';
var nexthop6 = getSystemProperty("ddos_protect.nexthop6") || '100::1';
var localpref = getSystemProperty("ddos_protect.localpref") || '100';

var route_max = getSystemProperty("ddos_protect.maxroutes") || '1000';
var flowspec_max = getSystemProperty("ddos_protect.maxflows") || '100';

var ipv6_enable = getSystemProperty("ddos_protect.enable.ipv6") === 'yes';
var flowspec_enable = getSystemProperty("ddos_protect.enable.flowspec") === 'yes';
var flowspec6_enable = getSystemProperty("ddos_protect.enable.flowspec6") === 'yes';

var flowspec_dscp = getSystemProperty("ddos_protect.flowspec.dscp") || 'le';
var flowspec_rate = getSystemProperty("ddos_protect.flowspec.rate") || 12500; // 100Kbps
var flowspec_redirect_method = getSystemProperty("ddos_protect.flowspec.redirect.method") || 'as';
var flowspec_redirect_as = getSystemProperty("ddos_protect.flowspec.redirect.as") || '65000:666';
var flowspec_redirect_as4 = getSystemProperty("ddos_protect.flowspec.redirect.as4") || '65000:666';
var flowspec_redirect_ip = getSystemProperty("ddos_protect.flowspec.redirect.ip") || '192.0.2.1:666';
var flowspec_redirect_nexthop = getSystemProperty("ddos_protect.flowspec.redirect.nexthop") || '192.0.2.1';
var flowspec_redirect_nexthop6 = getSystemProperty("ddos_protect.flowspec.redirect.nexthop6") || '100::1';
var flowspec_community = getSystemProperty("ddos_protect.flowspec.community") || '128:6:0'; // drop

var effectiveSamplingRateFlag = getSystemProperty("ddos_protect.esr") === 'yes';
var flow_t = getSystemProperty("ddos_protect.flow_seconds") || '2';
var threshold_t = getSystemProperty("ddos_protect.threshold_seconds") || '60';

var externalGroup = getSystemProperty("ddos_protect.externalgroup") || 'external';
var excludedGroups = getSystemProperty("ddos_protect.excludedgroups") || 'external,private,multicast,exclude';

var syslogHost = getSystemProperty("ddos_protect.syslog.host");
var syslogPort = getSystemProperty("ddos_protect.syslog.port") || '514';
var syslogFacility = getSystemProperty("ddos_protect.syslog.facility") || '16'; // local0
var syslogSeverity = getSystemProperty("ddos_protect.syslog.severity") || '5';  // notice

var routers = router.split(',');

function sendEvent(action,attack,target,group,protocol) {
  if(!syslogHost) return;

  var msg = {app:'ddos-protect',action:action,attack:attack,ip:target,group:group,protocol:protocol};
  try {
    syslog(syslogHost,syslogPort,syslogFacility,syslogSeverity,msg);
  } catch(e) {
    logWarning('DDoS cannot send syslog to ' + syslogHost); 
  }
}

var defaultGroups = {
  external:['0.0.0.0/0','::/0'],
  private:['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','169.254.0.0/16','fc00::/7'],
  multicast:['224.0.0.0/4','ff00::/8']
};

getSystemPropertyNames()
  .filter(p => p.match('^ddos_protect\\.group\\.'))
  .forEach(function(prop) {
    var [,,name] = prop.split('.');
    defaultGroups[name] = getSystemProperty(prop).split(',');
});

var groups = storeGet('groups') || defaultGroups;

var defaultSettings = {
  ip_flood:{threshold:1000000, timeout:180, action:'ignore'},
  ip_fragmentation:{threshold:500000, timeout:60, action:'ignore'},
  icmp_flood:{threshold:500000, timeout:60, action:'ignore'},
  udp_amplification:{threshold:500000, timeout:60, action:'ignore'},
  udp_flood:{threshold:500000, timeout:60, action:'ignore'},
  tcp_flood:{threshold:500000, timeout:60, action:'ignore'}
};
Object.keys(defaultSettings).forEach(function(key) {
  var val = defaultSettings[key];
  val.threshold = getSystemProperty('ddos_protect.'+key+'.threshold') || val.threshold;
  val.timeout = getSystemProperty('ddos_protect.'+key+'.timeout') || val.timeout;
  val.action = getSystemProperty('ddos_protect.'+key+'.action') || val.action;
});
var settings = storeGet('settings') || defaultSettings;

var controls = {};

var controlsUpdate = 0;
var counts = {};
function updateControlCounts() {
  controlsUpdate++;
  counts = {n:0, blocked:0, pending:0, failed:0};
  for(var key in controls) {
    counts.n++;
    switch(controls[key].status) {
    case 'blocked':
      if(routers.reduce((flag, router_ip) => flag && controls[key].success[router_ip], true)) {
        counts.blocked++;
      } else {
        counts.failed++;
      }
      break;
    case 'pending':
      counts.pending++;
      break;
    } 
  }
}

var enabled = storeGet('enabled') || ("automatic" === getSystemProperty("ddos_protect.mode")) || false;

var bgpUp = {};

function bgpBlackHole(router_ip, ctl) {
  if(bgpRouteCount(router_ip) >= route_max) {
    logWarning("DDoS exceeds table limit, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
    ctl.success[router_ip] = false;
    return;
  }
  switch(ctl.ipversion) {
    case '4':
      if(bgpAddRoute(router_ip,{prefix:ctl.target,nexthop:nexthop,communities:community,localpref:localpref})) {
        ctl.success[router_ip] = true;
      } else {
        logWarning("DDoS failed, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.success[router_ip] = false;
      }
      break;
    case '6':
      if(ipv6_enable) {
        if(bgpAddRoute(router_ip,{prefix:ctl.target,nexthop:nexthop6,communities:community,localpref:localpref})) {
          ctl.success[router_ip] = true;
        } else {
          logWarning("DDoS failed, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.success[router_ip] = false;
        }
      } else {
        logWarning("DDoS IPv6 disabled, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.success[router_ip] = false;
      }
      break;
  }
}

function bgpFlowSpec(router_ip, ctl) {
  if(bgpFlowCount(router_ip) >= flowspec_max) {
    logWarning("DDoS exceeds Flowspec table limit, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
    ctl.success[router_ip] = false;
    return;
  }
  switch(ctl.ipversion) {
    case '4': 
      if(flowspec_enable) {
        if(bgpAddFlow(router_ip,ctl.flowspec)) {
          ctl.success[router_ip] = true;
        } else {
          logWarning("DDoS failed, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.success[router_ip] = false;
        }
      } else {
        logWarning("DDoS Flowspec disabled, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.success[router_ip] = false;
      }
      break;
    case '6':
      if(flowspec6_enable) {
        if(bgpAddFlow(router_ip,ctl.flowspec)) {
          ctl.success[router_ip] = true;
        } else {
          logWarning("DDoS failed, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.success[router_ip] = false;
        }
      } else {
        logWarning("DDoS IPv6 Flowspec disabled, router "+router_ip+", "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.success[router_ip] = false;
      }
      break;
  }
}

function bgpAddControl(router_ip, ctl) {
  switch(ctl.action) {
    case 'drop':
      bgpBlackHole(router_ip, ctl); 
      break;
    case 'filter':
      ctl.flowspec.then={'traffic-rate':'0'};
      bgpFlowSpec(router_ip, ctl);
      break;
    case 'mark':
      ctl.flowspec.then={'traffic-marking':flowspec_dscp};
      bgpFlowSpec(router_ip, ctl);
      break;
    case 'limit':
      ctl.flowspec.then={'traffic-rate':flowspec_rate};
      bgpFlowSpec(router_ip, ctl);
      break;
    case 'redirect':
      ctl.flowspec.then={};
      switch(flowspec_redirect_method) {
        case 'as':
          ctl.flowspec.then['redirect-as'] = flowspec_redirect_as;
          break;
        case 'as4':
          ctl.flowspec.then['redirect-as4'] = flowspec_redirect_as4;
          break;
        case 'ip':
          ctl.flowspec.then['redirect-ip'] = flowspec_redirect_ip;
          break;
        case 'nexthop':
          switch(ctl.ipversion) {
            case '4':
              ctl.flowspec.then['redirect-nexthop'] = flowspec_redirect_nexthop;
              break;
            case '6': 
              ctl.flowspec.then['redirect-nexthop'] = flowspec_redirect_nexthop6;
              break;
          }
          break;
      }
      bgpFlowSpec(router_ip, ctl);
      break;
    case 'community':
      ctl.flowspec.then={'communities':flowspec_community};
      bgpFlowSpec(router_ip, ctl);
      break;
    case 'ignore':
      break;
  }
}

function bgpRemoveControl(router_ip, ctl) {
  if(ctl.status !== 'blocked' || !ctl.success[router_ip]) return;

  switch(ctl.action) {
    case 'drop':
      bgpRemoveRoute(router_ip, ctl.target);
      break;
    case 'filter':
    case 'mark':
    case 'limit':
    case 'redirect':
    case 'community':
      bgpRemoveFlow(router_ip, ctl.flowspec);
      break;
    case 'ignore':
      break;
  }
}

function bgpOpen(router_ip) {
  bgpUp[router_ip] = true;

  // re-install controls
  for(var key in controls) {
    let ctl = controls[key];
    if(ctl.status === 'blocked') {
      bgpAddControl(router_ip, ctl);
    }
  }
  updateControlCounts();
}

function bgpClose(router_ip) {
  bgpUp[router_ip] = false;

  // update control status
  for(var key in controls) {
    let ctl = controls[key];
    if(ctl.status === 'blocked') {
      ctl.success[router_ip] = false;
    }
  }
  updateControlCounts();
}

var bgpOpts = {ipv6:ipv6_enable, flowspec:flowspec_enable, flowspec6:flowspec6_enable};
routers.forEach(router => bgpAddNeighbor(router, my_as, my_id, bgpOpts, bgpOpen, bgpClose));

setGroups('ddos_protect', groups);

// IPv4 attacks
var keys = 'ipdestination,group:ipdestination:ddos_protect';
var filter = 'first:stack:.:ip:ip6=ip&group:ipsource:ddos_protect='+externalGroup+'&group:ipdestination:ddos_protect!='+excludedGroups;
setFlow('ddos_protect_ip_flood', {
  keys: keys+',ipprotocol',
  value:'frames',
  filter:filter,
  t:flow_t
});
setFlow('ddos_protect_ip_fragmentation', {
  keys: keys+',ipprotocol',
  value:'frames',
  filter:'(ipflags=001|range:ipfragoffset:1=true)&'+filter,
  t:flow_t
});
setFlow('ddos_protect_udp_amplification', {
  keys:keys+',udpsourceport',
  value:'frames',
  filter:'ipprotocol=17&'+filter,
  t:flow_t
});
setFlow('ddos_protect_udp_flood', {
  keys:keys+',udpdestinationport',
  value:'frames',
  filter:'ipprotocol=17&'+filter,
  t:flow_t
});
setFlow('ddos_protect_icmp_flood', {
  keys:keys+',icmptype',
  value:'frames',
  filter:'ipprotocol=1&'+filter,
  t:flow_t
});
setFlow('ddos_protect_tcp_flood', {
  keys:keys+',tcpdestinationport',
  value:'frames',
  filter:'ipprotocol=6&'+filter,
  t:flow_t
});

// IPv6 attacks
var keys6 = 'ip6destination,group:ip6destination:ddos_protect';
var filter6 = 'first:stack:.:ip:ip6=ip6&group:ip6source:ddos_protect='+externalGroup+'&group:ip6destination:ddos_protect!='+excludedGroups;
setFlow('ddos_protect_ip6_flood', {
  keys: keys6+',ip6nexthdr',
  value:'frames',
  filter:filter6,
  t:flow_t
});
setFlow('ddos_protect_ip6_fragmentation', {
  keys: keys6+',ip6nexthdr',
  value:'frames',
  filter:'(ip6fragm=yes|range:ip6fragoffset:1=true)&'+filter6,
  t:flow_t
});
setFlow('ddos_protect_udp6_amplification', {
  keys:keys6+',udpsourceport',
  value:'frames',
  filter:'ip6nexthdr=17&'+filter6,
  t:flow_t
});
setFlow('ddos_protect_udp6_flood', {
  keys:keys6+',udpdestinationport',
  value:'frames',
  filter:'ip6nexthdr=17&'+filter6,
  t:flow_t
});
setFlow('ddos_protect_icmp6_flood', {
  keys:keys6+',icmp6type',
  value:'frames',
  filter:'ip6nexthdr=58&'+filter6,
  t:flow_t
});
setFlow('ddos_protect_tcp6_flood', {
  keys:keys6+',tcpdestinationport',
  value:'frames',
  filter:'ip6nexthdr=6&'+filter6,
  t:flow_t
});

function setThresholds() {
  setThreshold('ddos_protect_ip_flood',
    {metric:'ddos_protect_ip_flood', value:settings.ip_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_ip6_flood',
    {metric:'ddos_protect_ip6_flood', value:settings.ip_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_icmp_flood',
    {metric:'ddos_protect_icmp_flood', value:settings.icmp_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_icmp6_flood',
    {metric:'ddos_protect_icmp6_flood', value:settings.icmp_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_tcp_flood',
    {metric:'ddos_protect_tcp_flood', value:settings.tcp_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_tcp6_flood',
    {metric:'ddos_protect_tcp6_flood', value:settings.tcp_flood.threshold, byFlow:true, timeout:threshold_t}
  )
  setThreshold('ddos_protect_udp_flood',
    {metric:'ddos_protect_udp_flood', value:settings.udp_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_udp6_flood',
    {metric:'ddos_protect_udp6_flood', value:settings.udp_flood.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_udp_amplification',
    {metric:'ddos_protect_udp_amplification', value:settings.udp_amplification.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_udp6_amplification',
    {metric:'ddos_protect_udp6_amplification', value:settings.udp_amplification.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_ip_fragmentation',
    {metric:'ddos_protect_ip_fragmentation', value:settings.ip_fragmentation.threshold, byFlow:true, timeout:threshold_t}
  );
  setThreshold('ddos_protect_ip6_fragmentation',
    {metric:'ddos_protect_ip6_fragmentation', value:settings.ip_fragmentation.threshold, byFlow:true, timeout:threshold_t}
  );
}

setThresholds();

function applyControl(ctl) {
  ctl.action = settings[ctl.attack].action;
  if('ignore' === ctl.action) return;

  logInfo("DDoS "+ctl.action+" "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
  sendEvent(ctl.action,ctl.attack,ctl.target,ctl.group,ctl.protocol);

  controls[ctl.key] = ctl;
  if(enabled) {
    routers.forEach(router_ip => bgpAddControl(router_ip, ctl));
    ctl.status = 'blocked';
  }
  updateControlCounts();
}

function releaseControl(ctl) {
  // should we always do this? maybe it means that the control is ineffective and should be removed?
  // maybe if the operator initiated the removal we should go back to pending, but keep the record
  var evt = ctl.event;
  if(thresholdTriggered(evt.thresholdID,evt.agent,evt.dataSource+'.'+evt.metric,evt.flowKey)) {
     return;
  }
  
  logInfo("DDoS release "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
  sendEvent("release",ctl.attack,ctl.target,ctl.group,ctl.protocol);

  routers.forEach(router_ip => bgpRemoveControl(router_ip, ctl));
  delete controls[ctl.key];
  updateControlCounts();
}

function getControlForId(id) {
  var key, entry;
  for(key in controls) {
    entry = controls[key];
    if(id === entry.id) {
      return entry;
    }
  }
  return null;
}

function operatorConfirm(id) {
  var ctl = getControlForId(id);
  if(!ctl) return;
  routers.forEach(router_ip => bgpAddControl(router_ip, ctl));
  ctl.status = 'blocked';
  updateControlCounts();
}

function operatorIgnore(id) {
  var ctl = getControlForId(id);
  if(!ctl) return;
  routers.forEach(router_ip => bgpRemoveControl(router_ip, ctl));
  delete controls[ctl.key];
  updateControlCounts(); 
}

var idx = 0;
setEventHandler(function(evt) {
  var key = evt.thresholdID+'-'+evt.flowKey;
  if(controls[key]) return;

  // don't allow data from data sources with sampling rates close to threshold
  // avoids false positives due the insufficient samples
  if(effectiveSamplingRateFlag) {
    let dsInfo = datasourceInfo(evt.agent,evt.dataSource);
    if(!dsInfo) return;
    let rate = dsInfo.effectiveSamplingRate;
    if(!rate || rate > (evt.threshold / 10)) {
      logWarning("DDoS effectiveSampling rate "+rate+" too high for "+evt.agent);
      return;
    }
  }

  var [target,group,protocol] = evt.flowKey.split(',');

  var ctl = {
    id:'c' + idx++,
    time:evt.timestamp,
    status:'pending',
    key:key,
    target:target,
    group:group,
    protocol:protocol,
    flowspec:{},
    event:evt,
    success:{}
  };

  switch(evt.thresholdID) {
    case 'ddos_protect_ip_flood':
      ctl.attack = 'ip_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'='+protocol
      };
      break;
    case 'ddos_protect_ip6_flood':
      ctl.attack = 'ip_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'='+protocol
      };
      break;
    case 'ddos_protect_icmp_flood':
      ctl.attack = 'icmp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=1',
        'icmp-type':'='+protocol
      };
      break;
    case 'ddos_protect_icmp6_flood':
      ctl.attack = 'icmp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'=58',
        'icmp-type':'='+protocol
      };
      break;
    case 'ddos_protect_tcp_flood':
      ctl.attack = 'tcp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=6',
        'destination-port':'='+protocol
      }; 
      break;
    case 'ddos_protect_tcp6_flood':
      ctl.attack = 'tcp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'=6',
        'destination-port':'='+protocol
      };
      break;
    case 'ddos_protect_udp_flood':
      ctl.attack = 'udp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=17',
        'destination-port':'='+protocol
      };
      break;
    case 'ddos_protect_udp6_flood':
      ctl.attack = 'udp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'=17',
        'destination-port':'='+protocol
      };
      break;
    case 'ddos_protect_udp_amplification':
      ctl.attack = 'udp_amplification';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'=17',
        'source-port':'='+protocol
      };
      break;
    case 'ddos_protect_udp6_amplification':
      ctl.attack = 'udp_amplification';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'=17',
        'source-port':'='+protocol
      };
      break;
    case 'ddos_protect_ip_fragmentation':
      ctl.attack = 'ip_fragmentation';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'='+protocol,
        fragment:'=I'
      };
      break;
    case 'ddos_protect_ip6_fragmentation':
      ctl.attack = 'ip_fragmentation';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'='+protocol,
        fragment:'=I'
      };
      break;
  }
  applyControl(ctl);
},[
 'ddos_protect_ip_flood',
 'ddos_protect_ip6_flood',
 'ddos_protect_icmp_flood',
 'ddos_protect_icmp6_flood',
 'ddos_protect_tcp_flood',
 'ddos_protect_tcp6_flood',
 'ddos_protect_udp_flood',
 'ddos_protect_udp6_flood',
 'ddos_protect_udp_amplification',
 'ddos_protect_udp6_amplification',
 'ddos_protect_ip_fragmentation',
 'ddos_protect_ip6_fragmentation'
]);

var trend = new Trend(300,1);
var points;

function calculateTopN(metric_names,n,minVal) {
  var top, topN, i, lim;
  top = metric_names.reduce(function(accum,name) {
    return accum.concat(activeFlows('ALL',name,n,minVal,'max') || []);
  }, []);
  top.sort((a,b) => b.value - a.value);
  var topN = {};
 
  lim = Math.min(n,top.length);
  for(i = 0; i < lim; i++) {
    topN[top[i].key] = top[i].value;
  }
  return topN;
}

setIntervalHandler(function(now) {
  points = {};
  points['controls'] = counts.n || 0;
  points['controls_pending'] = counts.pending || 0;
  points['controls_failed'] = counts.failed || 0;
  points['controls_blocked'] = counts.blocked || 0;
  points['connections'] = routers.reduce((sum, router_ip) => sum + (bgpUp[router_ip] ? 1 : 0), 0);
  points['top-5-ip-flood'] = calculateTopN(['ddos_protect_ip_flood','ddos_protect_ip6_flood'],5,1);
  points['top-5-ip-fragmentation'] = calculateTopN(['ddos_protect_ip_fragmentation','ddos_protect_ip6_fragmentation'],5,1);
  points['top-5-udp-flood'] = calculateTopN(['ddos_protect_udp_flood','ddos_protect_udp6_flood'],5,1);
  points['top-5-udp-amplification'] = calculateTopN(['ddos_protect_udp_amplification','ddos_protect_udp6_amplification'],5,1);
  points['top-5-icmp-flood'] = calculateTopN(['ddos_protect_icmp_flood','ddos_protect_icmp6_flood'],5,1);
  points['top-5-tcp-flood'] = calculateTopN(['ddos_protect_tcp_flood','ddos_protect_tcp6_flood'],5,1);
  trend.addPoints(now,points);

  for(var key in controls) {
    var ctl = controls[key];
    if(now - ctl.time > settings[ctl.attack].timeout * 60000) releaseControl(ctl);
  }
}, 1);

var settingsUpdate = 0;
function updateSettings(vals) {
  var newSettings = {};
  for(var attack in settings) {
    let entry = settings[attack];
    if(vals[attack]) {
      let newEntry = {};
      for(param in entry) {
        let val = vals[attack][param];
        if(val) {
          switch(param) {
            case 'action':
              if('ignore' === val
                 || 'drop' === val
                 || 'filter' === val
                 || 'mark' === val
                 || 'limit' === val
                 || 'redirect' === val
                 || 'community' === val) {
                newEntry[param] = val;
              } else {
                return false;
              }
              break;
            case 'threshold':
            case 'timeout':
              if(0 <= val) {
                newEntry[param] = val;
              } else {
                return false;
              }
              break;
          }
        } else {
          newEntry[param] = entry[param];
        }
      }
      newSettings[attack] = newEntry;  
    } else {
      newSettings[attack] = entry;
    }
  }
  settingsUpdate++;
  settings = newSettings;
  storeSet('settings',settings);
  setThresholds();
  return true; 
}

var groupsUpdate = 0;
setHttpHandler(function(req) {
  var result, key, entry, action, path = req.path;
  if(!path || path.length == 0) throw "not_found";
  switch(path[0]) {
    case 'trend':
      if(path.length > 1) throw "not_found";
      result = {
        controlsUpdate: controlsUpdate,
        settingsUpdate: settingsUpdate,
        groupsUpdate:groupsUpdate,
        mode: enabled ? 'automatic' : 'manual'
      };
      result.trend = req.query.after ? trend.after(parseInt(req.query.after)) : trend;
      result.trend.values = {};
      Object.keys(settings).forEach(function(key) { result.trend.values['threshold_'+key] = settings[key].threshold; });
      result.trend.values['threshold_connections'] = routers.length;
      break;
    case 'controls':
      result = {};
      switch(req.method) {
        case 'POST':
        case 'PUT':
          switch(req.body.action) {
            case 'block':
              operatorConfirm(req.body.id);
              break;
            case 'allow':
              operatorIgnore(req.body.id);
              break;
          }
          break;
      }
      result.controls = [];
      for(key in controls) {
        let ctl = controls[key];
        let status = ctl.status;
        if(status === 'blocked') {
           if(!routers.reduce((flag, router_ip) => flag && controls[key].success[router_ip], true)) {
             status = 'failed';
           }
        }
        let entry = {
          id: ctl.id,
          target: ctl.target,
          group: ctl.group,
          protocol: ctl.protocol,
          attack: ctl.attack,
          time: ctl.time,
          action: ctl.action,
          status: status 
        }
        result.controls.push(entry); 
      };
      result.update = controlsUpdate;
      break;
    case 'mode':
      if(path.length > 1) throw "not_found";
      enabled = 'automatic' === req.body;
      storeSet('enabled',enabled);
      settingsUpdate++; 
      result = enabled ? 'automatic' : 'manual';
      break;
    case 'settings':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request";
          if(!updateSettings(req.body)) throw "bad_request";
          break;
      }
      result = {
        update: settingsUpdate,
        mode: enabled ? 'automatic' : 'manual',
        settings: settings
      };
      break;
    case 'groups':
      if(path.length > 1) throw "not_found";
      switch(req.method) {
        case 'POST':
        case 'PUT':
          if(req.error) throw "bad_request";
          if(!setGroups('ddos_protect', req.body)) throw "bad_request";
          groups = req.body;
          storeSet('groups', groups);
          groupsUpdate++;
          break;
      }
      result = {
        update: groupsUpdate,
        groups: groups,
        external: externalGroup.split(','),
        excluded: excludedGroups.split(',')
      };
      break;
    default: throw 'not_found';
  }
  return result;
});
