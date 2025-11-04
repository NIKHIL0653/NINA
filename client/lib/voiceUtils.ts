interface VoiceSettings {
  rate: number;
  pitch: number;
  volume: number;
  voice?: SpeechSynthesisVoice;
}

// Extend window interface for speech recognition
declare global {
  interface Window {
    SpeechRecognition: any;
    webkitSpeechRecognition: any;
  }
}

class VoiceManager {
  private recognition: any = null;
  private synthesis: SpeechSynthesis = window.speechSynthesis;
  private isListening = false;
  private settings: VoiceSettings = {
    rate: 0.8,
    pitch: 1,
    volume: 0.8
  };

  constructor() {
    this.initializeSpeechRecognition();
  }

  private initializeSpeechRecognition() {
    // Check for browser support
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

    if (SpeechRecognition) {
      this.recognition = new SpeechRecognition();
      this.recognition.continuous = false;
      this.recognition.interimResults = false;
      this.recognition.lang = 'en-US';

      this.recognition.onstart = () => {
        this.isListening = true;
      };

      this.recognition.onend = () => {
        this.isListening = false;
      };

      this.recognition.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        this.isListening = false;
      };
    }
  }

  async startListening(onResult: (transcript: string) => void, onError?: (error: string) => void): Promise<void> {
    if (!this.recognition) {
      const error = 'Speech recognition is not supported in this browser';
      console.error(error);
      onError?.(error);
      return;
    }

    if (this.isListening) {
      console.warn('Already listening');
      return;
    }

    return new Promise((resolve, reject) => {
      if (!this.recognition) return reject('No recognition available');

      this.recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        onResult(transcript);
        resolve();
      };

      this.recognition.onerror = (event) => {
        const error = `Speech recognition error: ${event.error}`;
        console.error(error);
        onError?.(error);
        reject(new Error(error));
      };

      try {
        this.recognition.start();
      } catch (error) {
        console.error('Failed to start speech recognition:', error);
        onError?.('Failed to start voice input');
        reject(error);
      }
    });
  }

  stopListening(): void {
    if (this.recognition && this.isListening) {
      this.recognition.stop();
    }
  }

  speak(text: string, onEnd?: () => void): void {
    // Cancel any ongoing speech
    this.synthesis.cancel();

    const utterance = new SpeechSynthesisUtterance(text);

    // Apply settings
    utterance.rate = this.settings.rate;
    utterance.pitch = this.settings.pitch;
    utterance.volume = this.settings.volume;

    // Try to use a female voice for NINA (more calming)
    const voices = this.synthesis.getVoices();
    const preferredVoice = voices.find(voice =>
      voice.name.toLowerCase().includes('female') ||
      voice.name.toLowerCase().includes('woman') ||
      voice.name.toLowerCase().includes('samantha') ||
      voice.name.toLowerCase().includes('victoria')
    ) || voices.find(voice => voice.lang.startsWith('en'));

    if (preferredVoice) {
      utterance.voice = preferredVoice;
    }

    utterance.onend = () => {
      onEnd?.();
    };

    utterance.onerror = (event) => {
      console.error('Speech synthesis error:', event);
    };

    this.synthesis.speak(utterance);
  }

  stopSpeaking(): void {
    this.synthesis.cancel();
  }

  updateSettings(newSettings: Partial<VoiceSettings>): void {
    this.settings = { ...this.settings, ...newSettings };
  }

  getSettings(): VoiceSettings {
    return { ...this.settings };
  }

  isSupported(): boolean {
    return !!(window.SpeechRecognition || window.webkitSpeechRecognition);
  }

  isSpeaking(): boolean {
    return this.synthesis.speaking;
  }

  getAvailableVoices(): SpeechSynthesisVoice[] {
    return this.synthesis.getVoices();
  }
}

// Singleton instance
export const voiceManager = new VoiceManager();

// Utility functions for common use cases
export const speakResponse = (text: string): Promise<void> => {
  return new Promise((resolve) => {
    voiceManager.speak(text, resolve);
  });
};

export const listenForInput = (): Promise<string> => {
  return new Promise((resolve, reject) => {
    voiceManager.startListening(
      (transcript) => resolve(transcript),
      (error) => reject(new Error(error))
    );
  });
};

// Accessibility helpers
export const announceToScreenReader = (text: string): void => {
  const announcement = document.createElement('div');
  announcement.setAttribute('aria-live', 'polite');
  announcement.setAttribute('aria-atomic', 'true');
  announcement.style.position = 'absolute';
  announcement.style.left = '-10000px';
  announcement.style.width = '1px';
  announcement.style.height = '1px';
  announcement.style.overflow = 'hidden';

  document.body.appendChild(announcement);
  announcement.textContent = text;

  setTimeout(() => {
    document.body.removeChild(announcement);
  }, 1000);
};