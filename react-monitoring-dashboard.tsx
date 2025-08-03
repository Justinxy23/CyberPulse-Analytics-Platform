import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Area, AreaChart } from 'recharts';
import { AlertCircle, Shield, Activity, Users, Lock, Database, Cloud, Cpu, HardDrive, Wifi, AlertTriangle, CheckCircle, XCircle, TrendingUp, TrendingDown, RefreshCw, Settings, Bell, Search, Filter, Download } from 'lucide-react';

const SecurityDashboard = () => {
  // State management
  const [securityScore, setSecurityScore] = useState(87);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [isLoading, setIsLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');

  // WebSocket connection for real-time updates
  useEffect(() => {
    const ws = new WebSocket('wss://api.cyberpulse.io/ws');
    
    ws.onopen = () => {
      console.log('WebSocket connected');
      setWsConnected(true);
    };
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      handleRealtimeUpdate(data);
    };
    
    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      setWsConnected(false);
    };
    
    ws.onclose = () => {
      console.log('WebSocket disconnected');
      setWsConnected(false);
      // Attempt reconnection after 5 seconds
      setTimeout(() => {
        // Reconnection logic
      }, 5000);
    };
    
    return () => ws.close();
  }, []);

  // Fetch initial data
  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30s
    return () => clearInterval(interval);
  }, [selectedTimeRange]);

  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      // Simulated API call - replace with actual API
      const mockData = generateMockData();
      setSecurityScore(mockData.securityScore);
      setAlerts(mockData.alerts);
      setEvents(mockData.events);
      setMetrics(mockData.metrics);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    }
    setIsLoading(false);
  };

  const handleRealtimeUpdate = (data) => {
    switch (data.channel) {
      case 'security_events':
        setEvents(prev => [data.data, ...prev].slice(0, 100));
        break;
      case 'security_alerts':
        setAlerts(prev => [data.data, ...prev].slice(0, 50));
        break;
      case 'metrics_update':
        setMetrics(prev => ({ ...prev, ...data.data }));
        break;
      default:
        break;
    }
  };

  // Mock data generator
  const generateMockData = () => {
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const eventTypes = ['BRUTE_FORCE', 'SQL_INJECTION', 'MALWARE', 'DDoS', 'DATA_EXFILTRATION'];
    
    return {
      securityScore: 85 + Math.random() * 10,
      alerts: Array.from({ length: 10 }, (_, i) => ({
        id: `alert-${i}`,
        title: `Security Alert ${i + 1}`,
        severity: severities[Math.floor(Math.random() * severities.length)],
        timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
        status: Math.random() > 0.3 ? 'OPEN' : 'RESOLVED'
      })),
      events: Array.from({ length: 20 }, (_, i) => ({
        id: `event-${i}`,
        type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
        sourceIp: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        severity: severities[Math.floor(Math.random() * severities.length)],
        timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString()
      })),
      metrics: {
        totalEvents24h: Math.floor(Math.random() * 2000) + 1000,
        criticalAlerts: Math.floor(Math.random() * 10),
        blockedAttacks: Math.floor(Math.random() * 500) + 100,
        vulnerabilities: Math.floor(Math.random() * 50) + 10
      }
    };
  };

  // Chart data preparation
  const threatTrendData = useMemo(() => {
    const hours = Array.from({ length: 24 }, (_, i) => i);
    return hours.map(hour => ({
      hour: `${hour}:00`,
      threats: Math.floor(Math.random() * 50) + 10,
      blocked: Math.floor(Math.random() * 40) + 5
    }));
  }, []);

  const severityDistribution = useMemo(() => {
    const distribution = [
      { name: 'Critical', value: alerts.filter(a => a.severity === 'CRITICAL').length, color: '#ef4444' },
      { name: 'High', value: alerts.filter(a => a.severity === 'HIGH').length, color: '#f59e0b' },
      { name: 'Medium', value: alerts.filter(a => a.severity === 'MEDIUM').length, color: '#3b82f6' },
      { name: 'Low', value: alerts.filter(a => a.severity === 'LOW').length, color: '#10b981' }
    ];
    return distribution;
  }, [alerts]);

  const complianceData = [
    { framework: 'SOC2', score: 95, fullMark: 100 },
    { framework: 'HIPAA', score: 88, fullMark: 100 },
    { framework: 'PCI-DSS', score: 76, fullMark: 100 },
    { framework: 'ISO27001', score: 82, fullMark: 100 },
    { framework: 'NIST', score: 90, fullMark: 100 }
  ];

  // Filtered data
  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase());
      const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity;
      return matchesSearch && matchesSeverity;
    });
  }, [alerts, searchTerm, filterSeverity]);

  // Utility functions
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-500';
      case 'HIGH': return 'text-orange-500';
      case 'MEDIUM': return 'text-blue-500';
      case 'LOW': return 'text-green-500';
      default: return 'text-gray-500';
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
    return date.toLocaleDateString();
  };

  // Export functionality
  const exportData = () => {
    const data = {
      timestamp: new Date().toISOString(),
      securityScore,
      alerts: filteredAlerts,
      events,
      metrics
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyberpulse-report-${new Date().toISOString()}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-400 to-purple-600 bg-clip-text text-transparent">
              CyberPulse Analytics
            </h1>
            <p className="text-gray-400 mt-2">Real-Time Security Operations Center</p>
          </div>
          
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded-full ${wsConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
              <span className="text-sm">{wsConnected ? 'Connected' : 'Disconnected'}</span>
            </div>
            
            <button
              onClick={fetchDashboardData}
              className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors"
              disabled={isLoading}
            >
              <RefreshCw className={`w-5 h-5 ${isLoading ? 'animate-spin' : ''}`} />
            </button>
            
            <button className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors">
              <Bell className="w-5 h-5" />
            </button>
            
            <button className="p-2 rounded-lg bg-gray-800 hover:bg-gray-700 transition-colors">
              <Settings className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap gap-4">
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 focus:border-blue-500 outline-none"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          
          <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-800 border border-gray-700">
            <Search className="w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search alerts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-transparent outline-none text-sm w-48"
            />
          </div>
          
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-4 py-2 rounded-lg bg-gray-800 border border-gray-700 focus:border-blue-500 outline-none"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          
          <button
            onClick={exportData}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 transition-colors flex items-center gap-2"
          >
            <Download className="w-4 h-4" />
            Export Report
          </button>
        </div>
      </div>

      {/* Main Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Security Score */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Security Score</h3>
            <Shield className="w-6 h-6 text-blue-400" />
          </div>
          <div className="text-4xl font-bold mb-2">{securityScore.toFixed(1)}/100</div>
          <div className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-green-500" />
            <span className="text-sm text-green-500">+5.2% from last week</span>
          </div>
          <div className="mt-4 h-2 bg-gray-700 rounded-full overflow-hidden">
            <div 
              className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-500"
              style={{ width: `${securityScore}%` }}
            />
          </div>
        </div>

        {/* Active Threats */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Active Threats</h3>
            <AlertCircle className="w-6 h-6 text-red-400" />
          </div>
          <div className="text-4xl font-bold mb-2">{metrics.criticalAlerts || 0}</div>
          <div className="text-sm text-gray-400">Critical alerts requiring attention</div>
          <div className="mt-4 flex gap-2">
            {['CRITICAL', 'HIGH', 'MEDIUM'].map((severity, i) => (
              <div key={severity} className="flex-1">
                <div className={`h-2 rounded-full ${
                  severity === 'CRITICAL' ? 'bg-red-500' :
                  severity === 'HIGH' ? 'bg-orange-500' : 'bg-blue-500'
                }`} style={{ opacity: 1 - i * 0.3 }} />
              </div>
            ))}
          </div>
        </div>

        {/* Events Today */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Events Today</h3>
            <Activity className="w-6 h-6 text-green-400" />
          </div>
          <div className="text-4xl font-bold mb-2">{metrics.totalEvents24h || 0}</div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">{metrics.blockedAttacks || 0} blocked</span>
          </div>
          <div className="mt-4 grid grid-cols-4 gap-1">
            {Array.from({ length: 16 }, (_, i) => (
              <div
                key={i}
                className={`h-2 rounded-sm ${
                  i < 12 ? 'bg-green-500' : 'bg-gray-700'
                }`}
                style={{ opacity: i < 12 ? 0.3 + (i / 12) * 0.7 : 1 }}
              />
            ))}
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold">Vulnerabilities</h3>
            <Lock className="w-6 h-6 text-yellow-400" />
          </div>
          <div className="text-4xl font-bold mb-2">{metrics.vulnerabilities || 0}</div>
          <div className="flex items-center gap-2">
            <TrendingDown className="w-4 h-4 text-green-500" />
            <span className="text-sm text-green-500">-12% from last scan</span>
          </div>
          <div className="mt-4 flex justify-between text-xs">
            <span>Critical: 3</span>
            <span>High: 8</span>
            <span>Medium: 15</span>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Threat Trend Chart */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Threat Activity (24h)</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={threatTrendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="hour" stroke="#9CA3AF" />
              <YAxis stroke="#9CA3AF" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
                labelStyle={{ color: '#9CA3AF' }}
              />
              <Legend />
              <Area 
                type="monotone" 
                dataKey="threats" 
                stackId="1"
                stroke="#EF4444" 
                fill="#EF4444" 
                fillOpacity={0.6}
                name="Detected Threats"
              />
              <Area 
                type="monotone" 
                dataKey="blocked" 
                stackId="1"
                stroke="#10B981" 
                fill="#10B981" 
                fillOpacity={0.6}
                name="Blocked Attacks"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <h3 className="text-lg font-semibold mb-4">Alert Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityDistribution}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {severityDistribution.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Compliance Radar */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 mb-8">
        <h3 className="text-lg font-semibold mb-4">Compliance Status</h3>
        <ResponsiveContainer width="100%" height={400}>
          <RadarChart data={complianceData}>
            <PolarGrid stroke="#374151" />
            <PolarAngleAxis dataKey="framework" stroke="#9CA3AF" />
            <PolarRadiusAxis angle={90} domain={[0, 100]} stroke="#9CA3AF" />
            <Radar
              name="Compliance Score"
              dataKey="score"
              stroke="#3B82F6"
              fill="#3B82F6"
              fillOpacity={0.6}
            />
            <Tooltip 
              contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151' }}
            />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* Active Alerts Table */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-lg font-semibold">Active Security Alerts</h3>
          <span className="text-sm text-gray-400">{filteredAlerts.length} alerts</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left border-b border-gray-700">
                <th className="pb-3 text-sm font-medium text-gray-400">Status</th>
                <th className="pb-3 text-sm font-medium text-gray-400">Severity</th>
                <th className="pb-3 text-sm font-medium text-gray-400">Alert</th>
                <th className="pb-3 text-sm font-medium text-gray-400">Time</th>
                <th className="pb-3 text-sm font-medium text-gray-400">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.slice(0, 10).map((alert) => (
                <tr key={alert.id} className="border-b border-gray-700 hover:bg-gray-700/50 transition-colors">
                  <td className="py-4">
                    {alert.status === 'OPEN' ? (
                      <XCircle className="w-5 h-5 text-red-500" />
                    ) : (
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    )}
                  </td>
                  <td className="py-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                      alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' :
                      alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-500' :
                      alert.severity === 'MEDIUM' ? 'bg-blue-500/20 text-blue-500' :
                      'bg-green-500/20 text-green-500'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-4">
                    <div>
                      <div className="font-medium">{alert.title}</div>
                      <div className="text-sm text-gray-400">ID: {alert.id}</div>
                    </div>
                  </td>
                  <td className="py-4 text-sm text-gray-400">
                    {formatTimestamp(alert.timestamp)}
                  </td>
                  <td className="py-4">
                    <button className="px-3 py-1 text-sm bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {filteredAlerts.length > 10 && (
          <div className="mt-4 text-center">
            <button className="text-blue-400 hover:text-blue-300 text-sm">
              View all {filteredAlerts.length} alerts →
            </button>
          </div>
        )}
      </div>

      {/* System Health Indicators */}
      <div className="mt-8 grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Cpu className="w-5 h-5 text-blue-400" />
            <span className="text-sm">CPU Usage</span>
          </div>
          <span className="text-sm font-medium">45.2%</span>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-green-400" />
            <span className="text-sm">Memory</span>
          </div>
          <span className="text-sm font-medium">62.8%</span>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <HardDrive className="w-5 h-5 text-yellow-400" />
            <span className="text-sm">Storage</span>
          </div>
          <span className="text-sm font-medium">38.5%</span>
        </div>
        
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Wifi className="w-5 h-5 text-purple-400" />
            <span className="text-sm">Network</span>
          </div>
          <span className="text-sm font-medium">12.3 ms</span>
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;