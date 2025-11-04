import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Mic,
  MicOff,
  Volume2,
  VolumeX,
  Settings,
  AlertCircle
} from 'lucide-react';
import { voiceManager } from '@/lib/voiceUtils';
import { cn } from '@/lib/utils';

interface VoiceControlsProps {
  onVoiceInput: (transcript: string) => void;
  onVoiceError?: (error: string) => void;
  disabled?: boolean;
  className?: string;
  showTTS?: boolean;
}

export default function VoiceControls({
  onVoiceInput,
  onVoiceError,
  disabled = false,
  className,
  showTTS = true
}: VoiceControlsProps) {
  const [isListening, setIsListening] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [voiceEnabled, setVoiceEnabled] = useState(false);
  const [speechEnabled, setSpeechEnabled] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Check feature settings
  const featureSettings = localStorage.getItem('featureSettings_user') ?
    JSON.parse(localStorage.getItem('featureSettings_user')!) : { voiceFeatures: true };

  if (!featureSettings.voiceFeatures) {
    return null;
  }

  useEffect(() => {
    // Check if voice features are supported
    const speechSupported = 'speechSynthesis' in window;
    const recognitionSupported = voiceManager.isSupported();

    setVoiceEnabled(recognitionSupported);
    setSpeechEnabled(speechSupported);

    if (!recognitionSupported && !speechSupported) {
      setError('Voice features not supported in this browser');
    } else if (!recognitionSupported) {
      setError('Voice input not supported');
    } else if (!speechSupported) {
      setError('Voice output not supported');
    }

    // Listen for speech synthesis state changes
    const handleSpeechStart = () => setIsSpeaking(true);
    const handleSpeechEnd = () => setIsSpeaking(false);

    if (speechSupported) {
      window.speechSynthesis.addEventListener('voiceschanged', () => {
        // Voices loaded
      });
    }

    return () => {
      if (speechSupported) {
        window.speechSynthesis.removeEventListener('voiceschanged', () => {});
      }
    };
  }, []);

  const handleVoiceInput = async () => {
    if (!voiceEnabled || disabled) return;

    try {
      setError(null);
      setIsListening(true);

      const transcript = await voiceManager.startListening(
        (text) => {
          onVoiceInput(text);
          setIsListening(false);
        },
        (error) => {
          setError(error);
          setIsListening(false);
          onVoiceError?.(error);
        }
      );
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Voice input failed';
      setError(errorMessage);
      setIsListening(false);
      onVoiceError?.(errorMessage);
    }
  };

  const stopVoiceInput = () => {
    voiceManager.stopListening();
    setIsListening(false);
  };

  const toggleSpeech = () => {
    if (isSpeaking) {
      voiceManager.stopSpeaking();
      setIsSpeaking(false);
    } else {
      setSpeechEnabled(!speechEnabled);
    }
  };

  return (
    <div className={cn("flex items-center space-x-2", className)}>
      {/* Voice Input Button */}
      {voiceEnabled && (
        <Button
          variant={isListening ? "destructive" : "outline"}
          size="sm"
          onClick={isListening ? stopVoiceInput : handleVoiceInput}
          disabled={disabled}
          className={cn(
            "transition-all duration-200",
            isListening && "animate-pulse bg-red-500 hover:bg-red-600"
          )}
          title={isListening ? "Stop listening" : "Start voice input"}
        >
          {isListening ? (
            <MicOff className="w-4 h-4" />
          ) : (
            <Mic className="w-4 h-4" />
          )}
          <span className="ml-1 text-xs hidden sm:inline">
            {isListening ? 'Listening...' : 'Voice'}
          </span>
        </Button>
      )}

      {/* Voice Output Toggle */}
      {speechEnabled && showTTS && (
        <Button
          variant="outline"
          size="sm"
          onClick={toggleSpeech}
          disabled={disabled || isSpeaking}
          className="transition-all duration-200"
          title={isSpeaking ? "Stop speaking" : "Toggle voice output"}
        >
          {isSpeaking ? (
            <VolumeX className="w-4 h-4" />
          ) : (
            <Volume2 className="w-4 h-4" />
          )}
          <span className="ml-1 text-xs hidden sm:inline">
            {isSpeaking ? 'Speaking...' : 'TTS'}
          </span>
        </Button>
      )}

      {/* Error Indicator */}
      {error && (
        <Badge variant="destructive" className="text-xs">
          <AlertCircle className="w-3 h-3 mr-1" />
          Voice Error
        </Badge>
      )}

      {/* Voice Settings (Future enhancement) */}
      <Button
        variant="ghost"
        size="sm"
        className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground"
        title="Voice settings"
        disabled
      >
        <Settings className="w-3 h-3" />
      </Button>
    </div>
  );
}