// CyberPulse Mobile Security Monitor
// Author: Justin Christopher Weaver
// React Native app for iOS/Android security monitoring

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  StyleSheet,
  Text,
  View,
  ScrollView,
  TouchableOpacity,
  RefreshControl,
  Alert,
  Animated,
  Dimensions,
  StatusBar,
  Platform,
  Vibration,
  AppState,
  SafeAreaView
} from 'react-native';
import {
  LineChart,
  BarChart,
  PieChart,
  ProgressChart
} from 'react-native-chart-kit';
import AsyncStorage from '@react-native-async-storage/async-storage';
import NetInfo from '@react-native-community/netinfo';
import PushNotification from 'react-native-push-notification';
import * as Keychain from 'react-native-keychain';
import FaceID from 'react-native-touch-id';
import Icon from 'react-native-vector-icons/MaterialIcons';

const { width, height } = Dimensions.get('window');

interface SecurityMetrics {
  securityScore: number;
  criticalAlerts: number;
  activeThreats: number;
  totalEvents: number;
  systemHealth: {
    cpu: number;
    memory: number;
    network: number;
  };
}

interface Alert {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  timestamp: string;
  description: string;
  acknowledged: boolean;
}

const CyberPulseMobile: React.FC = () => {
  // State management
  const [metrics, setMetrics] = useState<SecurityMetrics>({
    securityScore: 0,
    criticalAlerts: 0,
    activeThreats: 0,
    totalEvents: 0,
    systemHealth: { cpu: 0, memory: 0, network: 0 }
  });
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState(true);
  const [selectedTab, setSelectedTab] = useState('dashboard');
  
  // Animations
  const fadeAnim = useRef(new Animated.Value(0)).current;
  const pulseAnim = useRef(new Animated.Value(1)).current;
  const slideAnim = useRef(new Animated.Value(-100)).current;

  // Configure push notifications
  useEffect(() => {
    PushNotification.configure({
      onRegister: function (token) {
        console.log('TOKEN:', token);
      },
      onNotification: function (notification) {
        console.log('NOTIFICATION:', notification);
        handleNotification(notification);
      },
      permissions: {
        alert: true,
        badge: true,
        sound: true,
      },
      popInitialNotification: true,
      requestPermissions: true,
    });

    // Check network status
    const unsubscribe = NetInfo.addEventListener(state => {
      setConnectionStatus(state.isConnected || false);
    });

    // Handle app state changes
    const subscription = AppState.addEventListener('change', handleAppStateChange);

    // Authenticate user
    authenticateUser();

    return () => {
      unsubscribe();
      subscription.remove();
    };
  }, []);

  // Biometric authentication
  const authenticateUser = async () => {
    try {
      const biometryType = await FaceID.isSupported();
      
      if (biometryType) {
        FaceID.authenticate('Access CyberPulse Security Dashboard', {
          fallbackLabel: 'Use Passcode'
        })
          .then(() => {
            setIsAuthenticated(true);
            fadeIn();
            loadDashboardData();
          })
          .catch(error => {
            Alert.alert('Authentication Failed', 'Please try again');
          });
      } else {
        // Fallback to PIN/Password
        setIsAuthenticated(true);
        fadeIn();
        loadDashboardData();
      }
    } catch (error) {
      console.error('Authentication error:', error);
    }
  };

  // Animations
  const fadeIn = () => {
    Animated.timing(fadeAnim, {
      toValue: 1,
      duration: 1000,
      useNativeDriver: true,
    }).start();
  };

  const startPulse = () => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(pulseAnim, {
          toValue: 1.2,
          duration: 1000,
          useNativeDriver: true,
        }),
        Animated.timing(pulseAnim, {
          toValue: 1,
          duration: 1000,
          useNativeDriver: true,
        }),
      ])
    ).start();
  };

  // Load dashboard data
  const loadDashboardData = async () => {
    try {
      // Check cached data first
      const cachedData = await AsyncStorage.getItem('dashboardData');
      if (cachedData) {
        const parsed = JSON.parse(cachedData);
        setMetrics(parsed.metrics);
        setAlerts(parsed.alerts);
      }

      // Fetch fresh data
      await fetchDashboardData();
    } catch (error) {
      console.error('Error loading data:', error);
    }
  };

  const fetchDashboardData = async () => {
    try {
      // Get auth token from keychain
      const credentials = await Keychain.getInternetCredentials('cyberpulse');
      
      if (!credentials) {
        throw new Error('No credentials found');
      }

      const response = await fetch('https://api.cyberpulse.io/api/v1/mobile/dashboard', {
        headers: {
          'Authorization': `Bearer ${credentials.password}`,
          'X-Device-ID': await getDeviceId(),
        }
      });

      const data = await response.json();
      
      // Update state
      setMetrics(data.metrics);
      setAlerts(data.alerts);
      
      // Cache data
      await AsyncStorage.setItem('dashboardData', JSON.stringify({
        metrics: data.metrics,
        alerts: data.alerts,
        timestamp: new Date().toISOString()
      }));

      // Check for critical alerts
      const criticalAlerts = data.alerts.filter((a: Alert) => a.severity === 'CRITICAL');
      if (criticalAlerts.length > 0) {
        Vibration.vibrate([0, 500, 200, 500]);
        showCriticalAlertNotification(criticalAlerts[0]);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      Alert.alert('Connection Error', 'Unable to fetch latest data');
    }
  };

  const handleNotification = (notification: any) => {
    if (notification.data.severity === 'CRITICAL') {
      Vibration.vibrate([0, 500, 200, 500]);
    }
    
    // Navigate to alerts tab
    setSelectedTab('alerts');
    
    // Refresh data
    fetchDashboardData();
  };

  const showCriticalAlertNotification = (alert: Alert) => {
    PushNotification.localNotification({
      title: '🚨 Critical Security Alert',
      message: alert.title,
      playSound: true,
      soundName: 'alarm.mp3',
      importance: 'high',
      vibrate: true,
      vibration: 500,
      data: alert,
    });
  };

  const handleAppStateChange = (nextAppState: string) => {
    if (nextAppState === 'active') {
      // App came to foreground
      fetchDashboardData();
    }
  };

  const getDeviceId = async (): Promise<string> => {
    let deviceId = await AsyncStorage.getItem('deviceId');
    if (!deviceId) {
      deviceId = Math.random().toString(36).substring(7);
      await AsyncStorage.setItem('deviceId', deviceId);
    }
    return deviceId;
  };

  const onRefresh = useCallback(() => {
    setRefreshing(true);
    fetchDashboardData().finally(() => setRefreshing(false));
  }, []);

  const acknowledgeAlert = async (alertId: string) => {
    try {
      // API call to acknowledge
      const updatedAlerts = alerts.map(a => 
        a.id === alertId ? { ...a, acknowledged: true } : a
      );
      setAlerts(updatedAlerts);
      
      // Haptic feedback
      Vibration.vibrate(50);
    } catch (error) {
      console.error('Error acknowledging alert:', error);
    }
  };

  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f59e0b';
      case 'MEDIUM': return '#3b82f6';
      case 'LOW': return '#10b981';
      default: return '#6b7280';
    }
  };

  const chartConfig = {
    backgroundColor: '#1f2937',
    backgroundGradientFrom: '#111827',
    backgroundGradientTo: '#1f2937',
    decimalPlaces: 0,
    color: (opacity = 1) => `rgba(59, 130, 246, ${opacity})`,
    labelColor: (opacity = 1) => `rgba(156, 163, 175, ${opacity})`,
    style: {
      borderRadius: 16,
    },
    propsForDots: {
      r: '6',
      strokeWidth: '2',
      stroke: '#3b82f6',
    },
  };

  // Render loading screen
  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <View style={styles.loadingContainer}>
          <Icon name="security" size={80} color="#3b82f6" />
          <Text style={styles.loadingText}>Authenticating...</Text>
        </View>
      </View>
    );
  }

  // Main dashboard
  const renderDashboard = () => (
    <Animated.View style={{ opacity: fadeAnim }}>
      {/* Security Score Card */}
      <View style={styles.scoreCard}>
        <Text style={styles.scoreTitle}>Security Score</Text>
        <Animated.View style={{ transform: [{ scale: pulseAnim }] }}>
          <ProgressChart
            data={{
              data: [metrics.securityScore / 100],
            }}
            width={width - 40}
            height={220}
            strokeWidth={16}
            radius={80}
            chartConfig={{
              ...chartConfig,
              color: (opacity = 1) => {
                const score = metrics.securityScore;
                if (score >= 80) return `rgba(16, 185, 129, ${opacity})`;
                if (score >= 60) return `rgba(245, 158, 11, ${opacity})`;
                return `rgba(239, 68, 68, ${opacity})`;
              },
            }}
            hideLegend={true}
          />
        </Animated.View>
        <Text style={styles.scoreValue}>{metrics.securityScore}/100</Text>
      </View>

      {/* Metrics Grid */}
      <View style={styles.metricsGrid}>
        <TouchableOpacity style={[styles.metricCard, styles.criticalCard]}>
          <Icon name="error" size={30} color="#ef4444" />
          <Text style={styles.metricValue}>{metrics.criticalAlerts}</Text>
          <Text style={styles.metricLabel}>Critical Alerts</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.metricCard}>
          <Icon name="warning" size={30} color="#f59e0b" />
          <Text style={styles.metricValue}>{metrics.activeThreats}</Text>
          <Text style={styles.metricLabel}>Active Threats</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.metricCard}>
          <Icon name="shield" size={30} color="#10b981" />
          <Text style={styles.metricValue}>{metrics.totalEvents}</Text>
          <Text style={styles.metricLabel}>Events Today</Text>
        </TouchableOpacity>

        <TouchableOpacity style={styles.metricCard}>
          <Icon name="speed" size={30} color="#3b82f6" />
          <Text style={styles.metricValue}>{metrics.systemHealth.cpu}%</Text>
          <Text style={styles.metricLabel}>System Load</Text>
        </TouchableOpacity>
      </View>

      {/* Threat Trend Chart */}
      <View style={styles.chartCard}>
        <Text style={styles.chartTitle}>24-Hour Threat Activity</Text>
        <LineChart
          data={{
            labels: ['00', '04', '08', '12', '16', '20'],
            datasets: [{
              data: [20, 45, 28, 80, 99, 43],
            }],
          }}
          width={width - 40}
          height={200}
          chartConfig={chartConfig}
          bezier
          style={styles.chart}
        />
      </View>
    </Animated.View>
  );

  // Render alerts
  const renderAlerts = () => (
    <View style={styles.alertsContainer}>
      {alerts.length === 0 ? (
        <View style={styles.emptyState}>
          <Icon name="check-circle" size={60} color="#10b981" />
          <Text style={styles.emptyStateText}>No active alerts</Text>
        </View>
      ) : (
        alerts.map((alert) => (
          <TouchableOpacity
            key={alert.id}
            style={[
              styles.alertCard,
              alert.acknowledged && styles.acknowledgedAlert
            ]}
            onPress={() => !alert.acknowledged && acknowledgeAlert(alert.id)}
          >
            <View style={styles.alertHeader}>
              <View style={[
                styles.severityBadge,
                { backgroundColor: getSeverityColor(alert.severity) }
              ]} />
              <Text style={styles.alertTitle}>{alert.title}</Text>
              {alert.acknowledged && (
                <Icon name="check" size={20} color="#10b981" />
              )}
            </View>
            <Text style={styles.alertDescription}>{alert.description}</Text>
            <Text style={styles.alertTime}>{alert.timestamp}</Text>
          </TouchableOpacity>
        ))
      )}
    </View>
  );

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#111827" />
      
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>CyberPulse</Text>
        <View style={styles.headerRight}>
          <View style={[
            styles.connectionIndicator,
            { backgroundColor: connectionStatus ? '#10b981' : '#ef4444' }
          ]} />
          <TouchableOpacity onPress={() => Alert.alert('Settings', 'Settings page')}>
            <Icon name="settings" size={24} color="#9ca3af" />
          </TouchableOpacity>
        </View>
      </View>

      {/* Main Content */}
      <ScrollView
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor="#3b82f6"
          />
        }
      >
        {selectedTab === 'dashboard' ? renderDashboard() : renderAlerts()}
      </ScrollView>

      {/* Tab Bar */}
      <View style={styles.tabBar}>
        <TouchableOpacity
          style={[styles.tab, selectedTab === 'dashboard' && styles.activeTab]}
          onPress={() => setSelectedTab('dashboard')}
        >
          <Icon 
            name="dashboard" 
            size={24} 
            color={selectedTab === 'dashboard' ? '#3b82f6' : '#6b7280'} 
          />
          <Text style={[
            styles.tabLabel,
            selectedTab === 'dashboard' && styles.activeTabLabel
          ]}>Dashboard</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.tab, selectedTab === 'alerts' && styles.activeTab]}
          onPress={() => setSelectedTab('alerts')}
        >
          <View>
            <Icon 
              name="notifications" 
              size={24} 
              color={selectedTab === 'alerts' ? '#3b82f6' : '#6b7280'} 
            />
            {metrics.criticalAlerts > 0 && (
              <View style={styles.badge}>
                <Text style={styles.badgeText}>{metrics.criticalAlerts}</Text>
              </View>
            )}
          </View>
          <Text style={[
            styles.tabLabel,
            selectedTab === 'alerts' && styles.activeTabLabel
          ]}>Alerts</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.tab}
          onPress={() => Alert.alert('Response', 'Incident Response')}
        >
          <Icon name="flash-on" size={24} color="#6b7280" />
          <Text style={styles.tabLabel}>Response</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={styles.tab}
          onPress={() => Alert.alert('Reports', 'Security Reports')}
        >
          <Icon name="assessment" size={24} color="#6b7280" />
          <Text style={styles.tabLabel}>Reports</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#111827',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  loadingText: {
    color: '#9ca3af',
    fontSize: 18,
    marginTop: 20,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 15,
    backgroundColor: '#1f2937',
    borderBottomWidth: 1,
    borderBottomColor: '#374151',
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#3b82f6',
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 15,
  },
  connectionIndicator: {
    width: 10,
    height: 10,
    borderRadius: 5,
  },
  scrollContent: {
    paddingBottom: 20,
  },
  scoreCard: {
    backgroundColor: '#1f2937',
    margin: 20,
    padding: 20,
    borderRadius: 16,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#374151',
  },
  scoreTitle: {
    fontSize: 18,
    color: '#9ca3af',
    marginBottom: 10,
  },
  scoreValue: {
    fontSize: 36,
    fontWeight: 'bold',
    color: '#ffffff',
    position: 'absolute',
    top: '50%',
    marginTop: -20,
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    paddingHorizontal: 15,
    gap: 10,
  },
  metricCard: {
    flex: 1,
    minWidth: (width - 50) / 2,
    backgroundColor: '#1f2937',
    padding: 20,
    borderRadius: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#374151',
  },
  criticalCard: {
    borderColor: '#ef4444',
  },
  metricValue: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#ffffff',
    marginVertical: 5,
  },
  metricLabel: {
    fontSize: 14,
    color: '#9ca3af',
  },
  chartCard: {
    backgroundColor: '#1f2937',
    margin: 20,
    padding: 20,
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#374151',
  },
  chartTitle: {
    fontSize: 18,
    color: '#ffffff',
    marginBottom: 15,
  },
  chart: {
    marginVertical: 8,
    borderRadius: 16,
  },
  alertsContainer: {
    padding: 20,
  },
  alertCard: {
    backgroundColor: '#1f2937',
    padding: 16,
    borderRadius: 12,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#374151',
  },
  acknowledgedAlert: {
    opacity: 0.6,
  },
  alertHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  severityBadge: {
    width: 12,
    height: 12,
    borderRadius: 6,
    marginRight: 10,
  },
  alertTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#ffffff',
    flex: 1,
  },
  alertDescription: {
    fontSize: 14,
    color: '#9ca3af',
    marginBottom: 8,
  },
  alertTime: {
    fontSize: 12,
    color: '#6b7280',
  },
  emptyState: {
    alignItems: 'center',
    paddingVertical: 60,
  },
  emptyStateText: {
    fontSize: 18,
    color: '#6b7280',
    marginTop: 15,
  },
  tabBar: {
    flexDirection: 'row',
    backgroundColor: '#1f2937',
    borderTopWidth: 1,
    borderTopColor: '#374151',
    paddingBottom: Platform.OS === 'ios' ? 20 : 10,
  },
  tab: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: 12,
  },
  activeTab: {
    borderTopWidth: 2,
    borderTopColor: '#3b82f6',
  },
  tabLabel: {
    fontSize: 12,
    color: '#6b7280',
    marginTop: 4,
  },
  activeTabLabel: {
    color: '#3b82f6',
  },
  badge: {
    position: 'absolute',
    top: -5,
    right: -10,
    backgroundColor: '#ef4444',
    borderRadius: 10,
    paddingHorizontal: 6,
    paddingVertical: 2,
  },
  badgeText: {
    color: '#ffffff',
    fontSize: 10,
    fontWeight: 'bold',
  },
});

export default CyberPulseMobile;