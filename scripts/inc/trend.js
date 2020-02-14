function Trend(maxPoints, stepSize) {
  this.maxPoints = maxPoints;
  this.trends = {};
  this.times = new Array(maxPoints);
  var i, t = (new Date()).getTime(), stepMs = stepSize * 1000;
  for(i = maxPoints - 1; i >= 0; i--) { t -= stepMs; this.times[i] = t; }
}

Trend.prototype.addPoints = function(now,values) {
  this.times.push(now);
  
  var name, i; 
  for (name in values) {
    var points = this.trends[name];
    if(!points) {
      points = new Array(this.maxPoints);
      for(i = 0; i < this.maxPoints; i++) points[i] = 0; 
      this.trends[name] = points;
    }
    points.push(values[name]);
    points.shift();
  }
  this.times.shift();
}

Trend.prototype.after = function(tval) {
  var res = new Trend(0,0);
  res.maxPoints = this.maxPoints;
  for(var i = 0; i < this.times.length; i++) {
    var t = this.times[i];
    if(tval < t) {
      res.times.push(t);
      for (var name in this.trends) {
        var val = this.trends[name][i];
        var trend = res.trends[name];
        if(!trend) {
          trend = [];
          res.trends[name] = trend;
        }
        trend.push(val);
      }
    }
  } 
  return res;
}

Trend.prototype.remove = function(name) {
  delete this.trends[name];
}
