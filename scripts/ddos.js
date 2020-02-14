// author: InMon
// version: 1.0
// date: 2/14/2020
// description: Use BGP to mitigate DDoS flood attacks
// copyright: Copyright (c) 2015-2020 InMon Corp.

include(scriptdir()+'/inc/trend.js');

var router_ip = getSystemProperty("ddos_protect.router") || '127.0.0.1';
var my_as     = getSystemProperty("ddos_protect.as") || '65000';
var my_id     = getSystemProperty("ddos_protect.id") || '0.6.6.6';
var community = getSystemProperty("ddos_protect.community") || '65535:666'; // RFC7999
var nexthop   = getSystemProperty("ddos_protect.nexthop") || '192.0.2.1';
var nexthop6  = getSystemProperty("ddos_protect.nexthop6") || '100::1';
var localpref = getSystemProperty("ddos_protect.localpref") || '100';

var route_max = getSystemProperty("ddos_protect.maxroutes") || '1000';
var flowspec_max = getSystemProperty("ddos_protect.maxflows") || '100';

var ipv6_enable = getSystemProperty("ddos_protect.enable.ipv6") === 'yes';
var flowspec_enable = getSystemProperty("ddos_protect.enable.flowspec") === 'yes';
var flowspec6_enable = getSystemProperty("ddos_protect.enable.flowspec6") === 'yes';

var flowspec_dscp = getSystemProperty("ddos_protect.flowspec.dscp") || 'le';
var flowspec_rate = getSystemProperty("ddos_protect.flowspec.rate") || 12500; // 100Kbps

var effectiveSamplingRateFlag = getSystemProperty("ddos_protect.esr") === 'yes';
var flow_t = getSystemProperty("ddos_protect.flow_seconds") || '2';
var threshold_t = getSystemProperty("ddos_protect.threshold_seconds") || '60';

var externalGroup = getSystemProperty("ddos_protect.externalgroup") || 'external';
var excludedGroups = getSystemProperty("ddos_protect.excludedgroups") || 'external,private,multicast,exclude';

var syslogHost = getSystemProperty("ddos_protect.syslog.host");
var syslogPort = getSystemProperty("ddos_protect.syslog.port") || '514';
var syslogFacility = getSystemProperty("ddos_protect.syslog.facility") || '16'; // local0
var syslogSeverity = getSystemProperty("ddos_protect.syslog.severity") || '5';  // notice

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
  for(var addr in controls) {
    counts.n++;
    switch(controls[addr].status) {
    case 'blocked':
      counts.blocked++;
      break;
    case 'pending':
      counts.pending++;
      break;
    case 'failed':
      counts.failed++;
      break;
    } 
  }
}

var enabled = storeGet('enabled') || ("automatic" === getSystemProperty("ddos_protect.mode")) || false;

var bgpUp = false;

function bgpBlackHole(ctl) {
  if(bgpRouteCount(router_ip) >= route_max) {
    logWarning("DDoS exceeds route table limit, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
    ctl.status = 'failed';
    return;
  }
  switch(ctl.ipversion) {
    case '4':
      if(bgpAddRoute(router_ip,{prefix:ctl.target,nexthop:nexthop,communities:community,localpref:localpref})) {
        ctl.status = 'blocked';
      } else {
        logWarning("DDoS failed, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.status = 'failed';
      }
      break;
    case '6':
      if(ipv6_enable) {
        if(bgpAddRoute(router_ip,{prefix:ctl.target,nexthop:nexthop6,communities:community,localpref:localpref})) {
          ctl.status = 'blocked';
        } else {
          logWarning("DDoS failed, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.status = 'failed';
        }
      } else {
        logWarning("DDoS IPv6 disabled, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.status = 'failed';
      }
      break;
  }
}

function bgpFlowSpec(ctl) {
  if(bgpFlowCount(router_ip) >= flowspec_max) {
    logWarning("DDoS exceeds FlowSpec table limit, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
    ctl.status = 'failed';
    return;
  }
  switch(ctl.ipversion) {
    case '4': 
      if(flowspec_enable) {
        if(bgpAddFlow(router_ip,ctl.flowspec)) {
          ctl.status = 'blocked';
        } else {
          logWarning("DDoS failed, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.status = 'failed';
        }
      } else {
        logWarning("DDoS FlowSpec disabled, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.status = 'failed';
      }
      break;
    case '6':
      if(flowspec6_enable) {
        if(bgpAddFlow(router_ip,ctl.flowspec)) {
          ctl.status = 'blocked';
        } else {
          logWarning("DDoS failed, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
          ctl.status = 'failed';
        }
      } else {
        logWarning("DDoS IPv6 FlowSpec disabled, "+ctl.attack+" "+ctl.target+" "+ctl.group+" "+ctl.protocol);
        ctl.status = 'failed';
      }
      break;
  }
}

function bgpAddControl(ctl) {
  switch(ctl.action) {
    case 'drop':
      bgpBlackHole(ctl); 
      break;
    case 'filter':
      ctl.flowspec.then={'traffic-rate':'0'};
      bgpFlowSpec(ctl);
      break;
    case 'mark':
      ctl.flowspec.then={'traffic-marking':flowspec_dscp};
      bgpFlowSpec(ctl);
      break;
    case 'limit':
      ctl.flowspec.then={'traffic-rate':flowspec_rate};
      bgpFlowSpec(ctl);
      break;
    case 'ignore':
      break;
  }
}

function bgpRemoveControl(ctl) {
  if(ctl.status !== 'blocked') return;

  switch(ctl.action) {
    case 'drop':
      bgpRemoveRoute(router_ip,ctl.target);
      break;
    case 'filter':
    case 'mark':
    case 'limit':
      bgpRemoveFlow(router_ip,ctl.flowspec);
      break;
    case 'ignore':
      break;
  }
}

function bgpOpen() {
  bgpUp = true;

  // re-install controls
  for(var key in controls) {
    let ctl = controls[key];
    if(ctl.status === 'blocked' || ctl.status === 'failed') {
      bgpAddControl(ctl);
    }
  }
  updateControlCounts();
}

function bgpClose() {
  bgpUp = false;

  // update control status
  for(var key in controls) {
    let ctl = controls[key];
    if(ctl.status === 'blocked') {
      ctl.status = 'failed';
    }
  }
  updateControlCounts();
}

var bgpOpts = {ipv6:ipv6_enable, flowspec:flowspec_enable, flowspec6:flowspec6_enable};
bgpAddNeighbor(router_ip, my_as, my_id, bgpOpts, bgpOpen, bgpClose);

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
  if(enabled) bgpAddControl(ctl);
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

  bgpRemoveControl(ctl);
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
  bgpAddControl(ctl);
  updateControlCounts();
}

function operatorIgnore(id) {
  var ctl = getControlForId(id);
  if(!ctl) return;
  bgpRemoveControl(ctl);
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
    time:Date.now(),
    status:'pending',
    key:key,
    target:target,
    group:group,
    protocol:protocol,
    flowspec:{},
    event:evt
  };

  switch(evt.thresholdID) {
    case 'ddos_protect_ip_flood':
      ctl.attack = 'ip_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:protocol
      };
      break;
    case 'ddos_protect_ip6_flood':
      ctl.attack = 'ip_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:protocol
      };
      break;
    case 'ddos_protect_icmp_flood':
      ctl.attack = 'icmp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'1',
        'icmp-type':protocol
      };
      break;
    case 'ddos_protect_icmp6_flood':
      ctl.attack = 'icmp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'58',
        'icmp-type':protocol
      };
      break;
    case 'ddos_protect_tcp_flood':
      ctl.attack = 'tcp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'6',
        'destination-port':protocol
      }; 
      break;
    case 'ddos_protect_tcp6_flood':
      ctl.attack = 'tcp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'6',
        'destination-port':protocol
      };
      break;
    case 'ddos_protect_udp_flood':
      ctl.attack = 'udp_flood';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'17',
        'destination-port':protocol
      };
      break;
    case 'ddos_protect_udp6_flood':
      ctl.attack = 'udp_flood';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'17',
        'destination-port':protocol
      };
      break;
    case 'ddos_protect_udp_amplification':
      ctl.attack = 'udp_amplification';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:'17',
        'source-port':protocol
      };
      break;
    case 'ddos_protect_udp6_amplification':
      ctl.attack = 'udp_amplification';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:'17',
        'source-port':protocol
      };
      break;
    case 'ddos_protect_ip_fragmentation':
      ctl.attack = 'ip_fragmentation';
      ctl.ipversion = '4';
      ctl.flowspec.match = {
        destination:target,
        version:'4',
        protocol:protocol,
        fragment:'I'
      };
      break;
    case 'ddos_protect_ip6_fragmentation':
      ctl.attack = 'ip_fragmentation';
      ctl.ipversion = '6';
      ctl.flowspec.match = {
        destination:target,
        version:'6',
        protocol:protocol,
        fragment:'I'
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
  points['connections'] = bgpUp ? 1 : 0;
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
              if('ignore' === val || 'drop' === val || 'filter' === val || 'mark' === val || 'limit' === val) {
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
        let entry = {
          id: ctl.id,
          target: ctl.target,
          group: ctl.group,
          protocol: ctl.protocol,
          attack: ctl.attack,
          time: ctl.time,
          action: ctl.action,
          status: ctl.status 
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
