$(function() {

  var dataURL = '../scripts/ddos.js/trend/json';
  var controlsURL = '../scripts/ddos.js/controls/json';
  var settingsURL = '../scripts/ddos.js/settings/json';
  var modeURL = '../scripts/ddos.js/mode/json';
  var groupsURL = '../scripts/ddos.js/groups/json';

  var enableFlowBrowserURL = '../../../app/browse-flows/status';

  var db = {};
  var showThreshold = true;
  var lastControlsID = 0;

  function setNav(target) {
    $('.navbar .nav-item a[href="'+target+'"]').parent().addClass('active').siblings().removeClass('active');
    $(target).show().siblings().hide();
    window.sessionStorage.setItem('ddos_protect_nav',target);
    window.history.replaceState(null,'',target);
  }

  var hash = window.location.hash;
  if(hash && $('.navbar .nav-item a[href="'+hash+'"]').length == 1) setNav(hash);
  else setNav(window.sessionStorage.getItem('ddos_protect_nav') || $('.navbar .nav-item a').first().attr('href'));

  $('.navbar .nav-link').on('click', function(e) {
    var selected = $(this).attr('href');
    setNav(selected);
    if('#charts' === selected) $.event.trigger({type:'updateChart'});
  });

  $('a[href^="#"]').on('click', function(e) {
    e.preventDefault();
  });

  var browseFlowsPage = '../../browse-flows/html/index.html';
  function openBrowseFlowsLink(id) {
    var trend = db.trend.trends['top-5-'+id];
    var latest = trend[trend.length - 1];
    var ipversion = '';
    var max = 0;
    for(var key in latest) {
      if(latest[key] < max) continue;
      max = latest[key];
      ipversion = key.indexOf(':') !== -1 ? '6' : '';
    }
    var parts = id.split('-');
    var specName = 'ddos_protect_' + parts[0] + ipversion + '_' + parts[1];
    $.get('../../../flow/'+specName+'/json', function(spec) {
      window.location.href=browseFlowsPage+'?keys='+encodeURIComponent(spec.keys)+'&value=fps&filter='+encodeURIComponent(spec.filter);
    }); 
  }

  $.get(enableFlowBrowserURL, function(status) {
    if(!'OK' === status) return;
    $('a.badge:hidden').show().click(function() {
      var id = $(this).parent().parent().find('.trend').attr('id');
      openBrowseFlowsLink(id);
    });
  });

  var protocols = {
    '1':'icmp',
    '6':'tcp',
    '17':'udp',
    '47':'gre',
    '50':'esp'
  };

  var ports = {
    '19':'chargen',
    '53':'dns',
    '80':'http',
    '123':'ntp',
    '137':'netbios',
    '161':'snmp',
    '389':'cldap',
    '443':'https',
    '1900':'ssdp',
    '4500':'ipsec'
  };

  function label(key,map) {
    var label = map[key];
    return label ? label+'('+key+')' : key; 
  }

  var colors = $.inmon.stripchart.prototype.options.colors;
  $('#ip-flood').chart({
    type: 'topn',
    stack: false,
    includeOther:false,
    metric: 'top-5-ip-flood',
    legendHeadings: ['Target','Group','Protocol'],
    keyName: (key,idx) => idx == 2 ? label(key,protocols) : key,
    hrule:[{name:'threshold_ip_flood',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#ip-fragmentation').chart({
    type: 'topn',
    stack: false,
    includeOther:false,
    metric: 'top-5-ip-fragmentation',
    legendHeadings: ['Target','Group','Protocol'],
    keyName: (key,idx) => idx == 2 ? label(key,protocols) : key,
    hrule:[{name:'threshold_ip_fragmentation',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#udp-flood').chart({
    type: 'topn',
    stack: false,
    includeOther: false,
    metric: 'top-5-udp-flood',
    legendHeadings: ['Target','Group','Port'],
    keyName: (key,idx) => idx == 2 ? label(key,ports) : key,
    hrule: [{name:'threshold_udp_flood',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#udp-amplification').chart({
    type: 'topn',
    stack: false,
    includeOther: false,
    metric: 'top-5-udp-amplification',
    legendHeadings: ['Target','Group','Port'],
    keyName: (key,idx) => idx == 2 ? label(key,ports) : key,
    hrule: [{name:'threshold_udp_amplification',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#tcp-flood').chart({
    type: 'topn',
    stack: false,
    includeOther: false,
    metric: 'top-5-tcp-flood',
    legendHeadings: ['Target','Group','Port'],
    keyName: (key,idx) => idx == 2 ? label(key,ports) : key,
    hrule: [{name:'threshold_tcp_flood',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#tcp-amplification').chart({
    type: 'topn',
    stack: false,
    includeOther: false,
    metric: 'top-5-tcp-amplification',
    legendHeadings: ['Target','Group','Port'],
    keyName: (key,idx) => idx == 2 ? label(key,ports) : key,
    hrule: [{name:'threshold_tcp_amplification',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#icmp-flood').chart({
    type: 'topn',
    stack: false,
    includeOther: false,
    metric: 'top-5-icmp-flood',
    legendHeadings: ['Target','Group','Type'],
    hrule: [{name:'threshold_icmp_flood',color:colors[1],scale:showThreshold}],
    units: 'Packets per Second'},
  db);
  $('#attacks').chart({
    type: 'trend',
    stack: true,
    legend: ['Active','Failed','Pending'],
    metrics: ['controls_blocked','controls_failed','controls_pending'],
    units: 'Number of Controls'},
  db);
  $('#connections').chart({
    type: 'trend',
    stack: false,
    metrics: ['connections'],
    hrule: [{name:'threshold_connections',color:colors[3],scale:showThreshold}],
    units: 'BGP Connections'},
  db);

  function updateControlsTable(controls) {
    var body, i, entry, html = '';
    body = $('#controlstable tbody');
    if(controls.length > 0) {
      controls.sort((x,y) => y.time - x.time);
      for(i = 0; i < controls.length; i++) {
        entry = controls[i];
        switch(entry.status) {
          case 'blocked':
            html += '<tr class="table-info" data-id="'+entry.id+'">';
            break;
          case 'pending':
            html += '<tr class="table-warning" data-id="'+entry.id+'">';
            break;;
          case 'failed':
            html += '<tr class="table-danger" data-id="'+entry.id+'">';
            break;
          default:
            html += '<tr>';
        }
        html += '<td>' + entry.target + '</td>';
        html += '<td>' + entry.group + '</td>';
        html += '<td>' + entry.attack + '</td>';
        html += '<td>' + entry.protocol + '</td>';
        html += '<td>' + (new Date(entry.time)).toLocaleTimeString('en-US') + '</td>';
        html += '<td>' + entry.action + '</td>';
        html += '<td>' + entry.status + '</td>'; 
        html += '</tr>';
        body.html(html);
        body.find('tr').click(function() {
          var row = $(this);
          var id = row.data('id');
          var dialog = $('#control-dialog');
          var target = $(row.children()[0]).html();
          var action = $(row.children()[5]).html();
          var status = $(row.children()[6]).html();
          dialog.data('id',id);
          dialog.data('action',action);
          dialog.find('#control-target').html(target);
          dialog.find('#control-group').html($(row.children()[1]).html());
          dialog.find('#control-attack').html($(row.children()[2]).html());
          dialog.find('#control-protocol').html($(row.children()[3]).html());
          dialog.find('#control-action').html(action);
          dialog.find('#control-install').prop('disabled','pending' !== status);
          dialog.modal('show');
        });
      } 
    } else {
       html = '<tr><td colspan="7" class="text-center"><em>No active controls</em></td></tr>'; 
       body.html(html);
    }
  }

  $('#control-remove').click(function() {
    var dialog = $('#control-dialog');
    var id = dialog.data('id');
    $.ajax({
      url:controlsURL,
      type:'POST',
      contentType:'application/json',
      dataType:'json',
      data:JSON.stringify({action:'allow',id:id}),
      success: function(data) {
        lastControlsUpdate = data.update;
        updateControlsTable(data.controls);
      },
      complete: function() {
        dialog.modal('hide');
      }
    });
  });

  $('#control-install').click(function() {
    var dialog = $('#control-dialog');
    var id = dialog.data('id');
    $.ajax({
      url:controlsURL,
      type:'POST',
      contentType:'application/json',
      data:JSON.stringify({action:'block',id:id}),
      success: function(data) {
        lastControlsUpdate = data.update;
        updateControlsTable(data.controls);
      },
      complete: function() {
        dialog.modal('hide');
      }
    }); 
  });

  var lastControlsUpdate = 0;
  function refreshControls() {
    $.ajax({
      url: controlsURL,
      dataType: 'json',
      success: function(data) {
        lastControlsUpdate = data.update;
        updateControlsTable(data.controls);
      }
    }); 
  }

  function updateSettings(settings) {
    $('#settingstable tbody tr').each(function(idx) {
      var row = $(this);
      row.removeClass('table-info table-active table-danger table-warning table-primary table-secondary table-success table-default');
      var cells = row.children();
      var attack = $(cells[0]).html();
      var vals = settings[attack];
      if(vals) {
        $(cells[1]).html(vals.action);
        $(cells[2]).html(vals.threshold);
        $(cells[3]).html(vals.timeout);
        switch(vals.action) {
          case 'drop':
            row.addClass('table-danger');
            break;
          case 'filter':
            row.addClass('table-warning');
            break;
          case 'mark':
            row.addClass('table-primary');
            break;
          case 'limit':
            row.addClass('table-secondary');
            break;
          case 'redirect':
            row.addClass('table-info');
            break;
          case 'community':
            row.addClass('table-active');
            break;
          case 'ignore':
            row.addClass('table-success');
            break;
          default:
            row.addClass('table-default');
        }
      }
    });
  }

  function updateMode(mode) {
    $('input:radio[name=controller_mode]').val([mode]);
  }

  $('input:radio[name=controller_mode]').click(function() {
    var mode = $(this).val();
    $.ajax({
      url: modeURL,
      type: 'POST',
      contentType:'application/json',
      data: JSON.stringify(mode),
      dataType:'json'
    });
  });

  var lastSettingsUpdate = 0;
  function refreshSettings() {
    $.ajax({
      url: settingsURL,
      dataType: 'json',
      success: function(data) {
        lastSettingsUpdate = data.update;
        updateSettings(data.settings);
        updateMode(data.mode);
      }
    });
  }
  refreshSettings();
 
  var groupInfo;
  function updateGroupsTable() {
    var body, i, names, name, entry, html = '', done = {};
    body = $('#groupstable tbody');
    for(i = 0; i < groupInfo.external.length; i++) {
      name = groupInfo.external[i];
      done[name] = name;
      entry = (groupInfo.groups[name] && groupInfo.groups[name].join(', ')) || '';
      html += '<tr class="table-danger"><td>'+name+'</td><td class="text-wrap">'+entry+'</td></tr>';
    }
    for(i = 0; i < groupInfo.excluded.length; i++) {
      name = groupInfo.excluded[i];
      if(done[name]) continue;
      done[name] = name;
      entry = (groupInfo.groups[name] && groupInfo.groups[name].join(', ')) || '';
      html += '<tr class="table-success"><td>'+name+'</td><td class="text-wrap">'+entry+'</td></tr>';
    }
    names = Object.keys(groupInfo.groups);
    names.sort();
    for(i = 0; i < names.length; i++) {
      name = names[i];
      if(done[name]) continue;
      entry = (groupInfo.groups[name] && groupInfo.groups[name].join(', ')) || '';
      html += '<tr class="table-warning"><td>'+name+'</td><td class="text-wrap">'+entry+'</td></tr>';
    } 
    body.html(html);
    body.find('tr').click(function() {
      var row = $(this);
      var dialog = $('#group-dialog');
      var name = $(row.children()[0]).html();
      var cidrs = $(row.children()[1]).html();
      dialog.data('name',name);
      dialog.find('#group-name').html(name);
      dialog.find('#group-cidrs').val(cidrs);
      dialog.modal('show');
    });
  }

  $('#group-submit').click(function() {
    var dialog = $('#group-dialog');
    var name = dialog.data('name');
    var cidrs = dialog.find('#group-cidrs').val().split(/[ ,]+/);
    groupInfo.groups[name] = cidrs;
    $.ajax({
      url:groupsURL,
      type:'POST',
      contentType:'application/json',
      data:JSON.stringify(groupInfo.groups),
      success: function(data) {
        lastGroupsUpdate = data.update;
        groupInfo = data;
        updateGroupsTable();
      },
      complete: function() {
        dialog.modal('hide');
      }
    });
  });

  $('#group-delete').click(function() {
    var dialog = $('#group-dialog');
    var name = dialog.data('name');
    delete groupInfo.groups[name];
    $.ajax({
      url:groupsURL,
      type:'POST',
      contentType:'application/json',
      data:JSON.stringify(groupInfo.groups),
      success: function(data) {
        lastGroupsUpdate = data.update;
        groupInfo = data;
        updateGroupsTable();
      },
      complete: function() {
        dialog.modal('hide');
      }
    });
  });

  $('#group-name').keyup(function() {
    $('#group-create').prop('disabled',$(this).val() === "");
  });

  $('#group-create').click(function() {
    var name = $('#group-name').val();
    $('#group-name').val('');
    if(groupInfo.groups[name]) return;
    groupInfo.groups[name] = [];
    $.ajax({
      url:groupsURL,
      type:'POST',
      contentType:'application/json',
      data:JSON.stringify(groupInfo.groups),
      success: function(data) {
        lastGroupsUpdate = data.update;
        groupInfo = data;
        updateGroupsTable();
      }
    });
  });

  var lastGroupsUpdate = 0;
  function refreshGroups() {
    $.ajax({
      url: groupsURL,
      dataType: 'json',
      success: function(data) {
        lastGroupsUpdate = data.update;
        groupInfo = data;
        updateGroupsTable();
      }
    });
  }
  refreshGroups();

  $('#settingstable tbody tr').click(function() {
    var row = $(this);
    var dialog = $('#setting-dialog');
    dialog.find('#setting-attack').html($(row.children()[0]).html());
    dialog.find('#setting-action').val($(row.children()[1]).html());
    dialog.find('#setting-threshold').val($(row.children()[2]).html());
    dialog.find('#setting-timeout').val($(row.children()[3]).html());
    dialog.modal('show');
  });

  $('#setting-submit').click(function() {
    var dialog = $('#setting-dialog');
    var attack = dialog.find('#setting-attack').html();
    var action = dialog.find('#setting-action').val();
    var threshold = dialog.find('#setting-threshold').val();
    var timeout = dialog.find('#setting-timeout').val();
    var msg = {};
    msg[attack] = {action:action,threshold:threshold,timeout:timeout};
    $.ajax({
      url:settingsURL,
      type:'POST',
      contentType:'application/json',
      data:JSON.stringify(msg),
      dataType:'json',
      success: function(data) {
        lastSettingsUpdate = data.update;
        updateSettings(data.settings);
        updateMode(data.mode);
      },
      complete: function() {
        dialog.modal('hide');
      }
    });
  });

  function updateData(data) {
    if(!data 
      || !data.trend 
      || !data.trend.times 
      || data.trend.times.length == 0) return;
    
    if(db.trend) {
      // merge in new data
      var maxPoints = db.trend.maxPoints;
      db.trend.times = db.trend.times.concat(data.trend.times);
      var remove = db.trend.times.length > maxPoints ? db.trend.times.length - maxPoints : 0;
      if(remove) db.trend.times = db.trend.times.slice(remove);
      for(var name in db.trend.trends) {
        db.trend.trends[name] = db.trend.trends[name].concat(data.trend.trends[name]);
        if(remove) db.trend.trends[name] = db.trend.trends[name].slice(remove);
      }
    } else db.trend = data.trend;
    
    db.trend.start = new Date(db.trend.times[0]);
    db.trend.end = new Date(db.trend.times[db.trend.times.length - 1]);
    db.trend.values = data.trend.values;

    $.event.trigger({type:'updateChart'});
  }

  (function pollTrends() {
    $.ajax({
      url: dataURL,
      dataType: 'json',
      data: db.trend && db.trend.end ? {after:db.trend.end.getTime()} : null,
      success: function(data) {
        if(data) {
          updateData(data);
          if(lastControlsUpdate !== data.controlsUpdate) refreshControls();
          if(lastSettingsUpdate != data.settingsUpdate) refreshSettings();
          if(lastGroupsUpdate != data.groupsUpdate) refreshGroups();
        } 
      },
      complete: function(result,status,errorThrown) {
        setTimeout(pollTrends,1000);
      },
      timeout: 60000
    });
  })();

  $(window).resize(function() {
    $.event.trigger({type:'updateChart'});
  });
});
