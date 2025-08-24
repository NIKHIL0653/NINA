import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  TrendingUp,
  TrendingDown,
  Activity,
  BarChart3,
  AlertCircle,
  CheckCircle,
  Clock,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface RecordAnalyticsProps {
  savedRecords: any[];
}

export default function RecordAnalytics({ savedRecords }: RecordAnalyticsProps) {
  if (savedRecords.length === 0) {
    return null;
  }

  // Calculate analytics
  const totalRecords = savedRecords.length;
  const uniqueTests = new Set(savedRecords.map(record => record.testId)).size;
  
  // Get recent records (last 30 days)
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  
  const recentRecords = savedRecords.filter(record => 
    new Date(record.date) >= thirtyDaysAgo
  );
  
  // Analyze parameter statuses
  const allParameters = savedRecords.flatMap(record => record.parameters);
  const statusCounts = allParameters.reduce((acc, param) => {
    if (param.status) {
      acc[param.status] = (acc[param.status] || 0) + 1;
    }
    return acc;
  }, {} as Record<string, number>);

  const normalPercentage = statusCounts.normal ? 
    Math.round((statusCounts.normal / allParameters.length) * 100) : 0;
  
  // Find most recent test
  const mostRecentRecord = savedRecords.reduce((latest, record) => 
    new Date(record.date) > new Date(latest.date) ? record : latest
  );

  // Find trends (compare recent vs older records)
  const olderRecords = savedRecords.filter(record => 
    new Date(record.date) < thirtyDaysAgo
  );
  
  const trendDirection = recentRecords.length > olderRecords.length ? 'up' : 
                        recentRecords.length < olderRecords.length ? 'down' : 'stable';

  return (
    <div className="space-y-6">
      <Card className="shadow-md border-0 bg-gradient-to-br from-blue-50 to-cyan-50 dark:from-blue-900/20 dark:to-cyan-900/20">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <BarChart3 className="w-5 h-5 text-blue-500" />
            <span>Health Analytics</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {/* Total Records */}
            <div className="text-center p-4 bg-white/60 dark:bg-gray-800/60 rounded-lg">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {totalRecords}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Total Records
              </div>
            </div>

            {/* Unique Tests */}
            <div className="text-center p-4 bg-white/60 dark:bg-gray-800/60 rounded-lg">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {uniqueTests}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Test Types
              </div>
            </div>

            {/* Recent Activity */}
            <div className="text-center p-4 bg-white/60 dark:bg-gray-800/60 rounded-lg">
              <div className="flex items-center justify-center space-x-1">
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {recentRecords.length}
                </div>
                {trendDirection === 'up' && <TrendingUp className="w-4 h-4 text-green-500" />}
                {trendDirection === 'down' && <TrendingDown className="w-4 h-4 text-red-500" />}
                {trendDirection === 'stable' && <Activity className="w-4 h-4 text-gray-500" />}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Last 30 Days
              </div>
            </div>

            {/* Health Score */}
            <div className="text-center p-4 bg-white/60 dark:bg-gray-800/60 rounded-lg">
              <div className="flex items-center justify-center space-x-1">
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {normalPercentage}%
                </div>
                {normalPercentage >= 80 ? 
                  <CheckCircle className="w-4 h-4 text-green-500" /> :
                  <AlertCircle className="w-4 h-4 text-yellow-500" />
                }
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                Normal Values
              </div>
            </div>
          </div>
        </CardContent>
      </Card>



      {/* Recent Activity */}
      <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Clock className="w-5 h-5 text-purple-500" />
            <span>Recent Activity</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
              <div>
                <p className="font-medium">Latest Test</p>
                <p className="text-sm text-muted-foreground">
                  {mostRecentRecord.testName}
                </p>
              </div>
              <div className="text-right">
                <p className="text-sm font-medium">{mostRecentRecord.date}</p>
                <p className="text-xs text-muted-foreground">
                  {mostRecentRecord.parameters.length} parameters
                </p>
              </div>
            </div>
            
            {recentRecords.length > 1 && (
              <div className="text-sm text-muted-foreground">
                You've been actively tracking your health with {recentRecords.length} records in the past month.
                {normalPercentage >= 80 ? 
                  " Most of your values are within normal ranges! 🎉" :
                  " Consider discussing any concerning values with your healthcare provider."
                }
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
