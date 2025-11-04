import React, { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Heart,
  Wind,
  MessageCircle,
  Phone,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Lightbulb,
  Users,
  BookOpen,
  AlertTriangle
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface AnxietySupportProps {
  anxietyLevel: number;
  showExpanded?: boolean;
  onClose?: () => void;
  className?: string;
}

export default function AnxietySupport({
  anxietyLevel,
  showExpanded = false,
  onClose,
  className
}: AnxietySupportProps) {
  const [expanded, setExpanded] = useState(showExpanded);

  const breathingExercises = [
    {
      name: "4-7-8 Breathing",
      description: "Inhale for 4 seconds, hold for 7 seconds, exhale for 8 seconds",
      duration: "1-2 minutes"
    },
    {
      name: "Box Breathing",
      description: "Inhale for 4, hold for 4, exhale for 4, hold for 4",
      duration: "2-5 minutes"
    },
    {
      name: "Deep Belly Breathing",
      description: "Place one hand on your belly, inhale deeply through nose, exhale slowly",
      duration: "3-5 minutes"
    }
  ];

  const supportResources = [
    {
      name: "National Alliance on Mental Illness (NAMI)",
      type: "helpline",
      contact: "1-800-950-6264",
      description: "Free mental health support and information"
    },
    {
      name: "Crisis Text Line",
      type: "text",
      contact: "Text HOME to 741741",
      description: "24/7 crisis support via text message"
    },
    {
      name: "Mental Health America",
      type: "website",
      contact: "mhanational.org",
      description: "Screening tools and local resources"
    },
    {
      name: "Anxiety & Depression Association of America",
      type: "website",
      contact: "adaa.org",
      description: "Information and treatment resources"
    }
  ];

  const mindfulnessTips = [
    "Take slow, deep breaths focusing on the sensation of air entering and leaving your body",
    "Ground yourself by naming 5 things you can see, 4 you can touch, 3 you can hear, 2 you can smell, and 1 you can taste",
    "Practice progressive muscle relaxation - tense and release each muscle group from your toes to your head",
    "Use positive affirmations like 'This feeling will pass' or 'I am safe in this moment'",
    "Step away for a short walk or change your environment if possible"
  ];

  const getAnxietyColor = () => {
    if (anxietyLevel >= 8) return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950';
    if (anxietyLevel >= 6) return 'border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-950';
    if (anxietyLevel >= 4) return 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950';
    return 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950';
  };

  const getAnxietyBadge = () => {
    if (anxietyLevel >= 8) return { label: 'High Anxiety', color: 'bg-red-100 text-red-800' };
    if (anxietyLevel >= 6) return { label: 'Moderate Anxiety', color: 'bg-orange-100 text-orange-800' };
    if (anxietyLevel >= 4) return { label: 'Mild Anxiety', color: 'bg-yellow-100 text-yellow-800' };
    return { label: 'Low Anxiety', color: 'bg-blue-100 text-blue-800' };
  };

  const badge = getAnxietyBadge();

  return (
    <Card className={cn("border-2 transition-all duration-300", getAnxietyColor(), className)}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Heart className="w-5 h-5 text-red-500" />
            <CardTitle className="text-lg">Anxiety Support</CardTitle>
            <Badge className={badge.color}>
              {badge.label}
            </Badge>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setExpanded(!expanded)}
            className="h-8 w-8 p-0"
          >
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Quick Breathing Exercise */}
        <div className="p-3 bg-white/50 dark:bg-gray-800/50 rounded-lg">
          <div className="flex items-center space-x-2 mb-2">
            <Wind className="w-4 h-4 text-blue-500" />
            <h4 className="font-medium text-sm">Quick Breathing Exercise</h4>
          </div>
          <p className="text-sm text-muted-foreground mb-2">
            Try this simple exercise: Inhale slowly for 4 counts, hold for 4, exhale for 4.
          </p>
          <Button size="sm" variant="outline" className="text-xs">
            Start 1-Minute Timer
          </Button>
        </div>

        {expanded && (
          <>
            {/* Breathing Exercises */}
            <div>
              <h4 className="font-medium mb-3 flex items-center space-x-2">
                <Wind className="w-4 h-4" />
                <span>Breathing Exercises</span>
              </h4>
              <div className="space-y-2">
                {breathingExercises.map((exercise, index) => (
                  <div key={index} className="p-3 bg-white/30 dark:bg-gray-800/30 rounded-lg">
                    <div className="flex justify-between items-start mb-1">
                      <h5 className="font-medium text-sm">{exercise.name}</h5>
                      <Badge variant="outline" className="text-xs">
                        {exercise.duration}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{exercise.description}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Mindfulness Tips */}
            <div>
              <h4 className="font-medium mb-3 flex items-center space-x-2">
                <Lightbulb className="w-4 h-4" />
                <span>Mindfulness Tips</span>
              </h4>
              <div className="space-y-2">
                {mindfulnessTips.map((tip, index) => (
                  <div key={index} className="flex items-start space-x-2">
                    <div className="w-1.5 h-1.5 bg-primary rounded-full mt-2 flex-shrink-0" />
                    <p className="text-sm text-muted-foreground">{tip}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Support Resources */}
            <div>
              <h4 className="font-medium mb-3 flex items-center space-x-2">
                <Users className="w-4 h-4" />
                <span>Support Resources</span>
              </h4>
              <div className="space-y-2">
                {supportResources.map((resource, index) => (
                  <div key={index} className="p-3 bg-white/30 dark:bg-gray-800/30 rounded-lg">
                    <div className="flex justify-between items-start mb-1">
                      <h5 className="font-medium text-sm">{resource.name}</h5>
                      <Badge variant="outline" className="text-xs capitalize">
                        {resource.type}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mb-2">{resource.description}</p>
                    <div className="flex items-center space-x-2">
                      {resource.type === 'helpline' && <Phone className="w-3 h-3" />}
                      {resource.type === 'text' && <MessageCircle className="w-3 h-3" />}
                      {resource.type === 'website' && <ExternalLink className="w-3 h-3" />}
                      <span className="text-xs font-medium">{resource.contact}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Professional Help Notice */}
            {anxietyLevel >= 7 && (
              <div className="p-3 bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-lg">
                <div className="flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-red-500 mt-0.5" />
                  <div>
                    <h5 className="font-medium text-sm text-red-800 dark:text-red-200">
                      Consider Professional Help
                    </h5>
                    <p className="text-xs text-red-700 dark:text-red-300 mt-1">
                      Your anxiety level suggests you may benefit from speaking with a mental health professional.
                      The resources above can help you find appropriate support.
                    </p>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {onClose && (
          <div className="flex justify-end pt-2">
            <Button variant="outline" size="sm" onClick={onClose}>
              Close Support
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}