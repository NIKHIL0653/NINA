import React from 'react';
import { Badge } from '@/components/ui/badge';
import {
  Heart,
  AlertTriangle,
  Meh,
  Frown,
  Angry,
  Smile,
  Shield,
  Clock
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface EmotionalIndicatorProps {
  emotion: 'anxiety' | 'fear' | 'frustration' | 'calm' | 'sadness' | 'anger' | 'neutral';
  confidence: number;
  anxietyLevel: number;
  urgency: 'low' | 'moderate' | 'high';
  className?: string;
}

export default function EmotionalIndicator({
  emotion,
  confidence,
  anxietyLevel,
  urgency,
  className
}: EmotionalIndicatorProps) {
  // Skip rendering if emotional indicators are disabled in settings
  const featureSettings = localStorage.getItem('featureSettings_user') ?
    JSON.parse(localStorage.getItem('featureSettings_user')!) : { emotionalIndicators: true };

  if (!featureSettings.emotionalIndicators) {
    return null;
  }
  const getEmotionConfig = () => {
    switch (emotion) {
      case 'anxiety':
        return {
          icon: Heart,
          label: 'Anxious',
          color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
          bgColor: 'bg-gradient-to-r from-yellow-50 to-orange-50 dark:from-yellow-950 dark:to-orange-950'
        };
      case 'fear':
        return {
          icon: AlertTriangle,
          label: 'Fearful',
          color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
          bgColor: 'bg-gradient-to-r from-red-50 to-pink-50 dark:from-red-950 dark:to-pink-950'
        };
      case 'frustration':
        return {
          icon: Angry,
          label: 'Frustrated',
          color: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
          bgColor: 'bg-gradient-to-r from-orange-50 to-red-50 dark:from-orange-950 dark:to-red-950'
        };
      case 'sadness':
        return {
          icon: Frown,
          label: 'Sad',
          color: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
          bgColor: 'bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-950 dark:to-indigo-950'
        };
      case 'anger':
        return {
          icon: Angry,
          label: 'Angry',
          color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
          bgColor: 'bg-gradient-to-r from-red-50 to-red-100 dark:from-red-950 dark:to-red-900'
        };
      case 'calm':
        return {
          icon: Smile,
          label: 'Calm',
          color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
          bgColor: 'bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-950 dark:to-emerald-950'
        };
      default:
        return {
          icon: Meh,
          label: 'Neutral',
          color: 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200',
          bgColor: 'bg-gradient-to-r from-gray-50 to-slate-50 dark:from-gray-950 dark:to-slate-950'
        };
    }
  };

  const getUrgencyConfig = () => {
    switch (urgency) {
      case 'high':
        return {
          icon: AlertTriangle,
          label: 'High Priority',
          color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
        };
      case 'moderate':
        return {
          icon: Clock,
          label: 'Moderate',
          color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
        };
      default:
        return {
          icon: Shield,
          label: 'Low Priority',
          color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
        };
    }
  };

  const config = getEmotionConfig();
  const urgencyConfig = getUrgencyConfig();
  const Icon = config.icon;
  const UrgencyIcon = urgencyConfig.icon;

  return (
    <div className={cn(
      "rounded-lg p-3 border transition-all duration-300",
      config.bgColor,
      className
    )}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center space-x-2">
          <Icon className="w-4 h-4" />
          <span className="text-sm font-medium">{config.label}</span>
        </div>
        <div className="flex items-center space-x-1">
          <UrgencyIcon className="w-3 h-3" />
          <span className="text-xs text-muted-foreground">{urgencyConfig.label}</span>
        </div>
      </div>

      <div className="space-y-2">
        {/* Anxiety Level Bar */}
        {emotion === 'anxiety' && (
          <div className="space-y-1">
            <div className="flex justify-between text-xs">
              <span>Anxiety Level</span>
              <span>{anxietyLevel}/10</span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-gradient-to-r from-yellow-400 to-red-500 h-2 rounded-full transition-all duration-500"
                style={{ width: `${(anxietyLevel / 10) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Confidence Score */}
        <div className="flex justify-between items-center text-xs">
          <span>Confidence</span>
          <Badge variant="outline" className="text-xs">
            {confidence}%
          </Badge>
        </div>
      </div>

      {/* Calming Message for High Anxiety */}
      {emotion === 'anxiety' && anxietyLevel >= 6 && (
        <div className="mt-3 p-2 bg-white/50 dark:bg-gray-800/50 rounded-md border border-white/20">
          <p className="text-xs text-muted-foreground">
            💙 Take a deep breath. You're doing the right thing by seeking information.
          </p>
        </div>
      )}
    </div>
  );
}