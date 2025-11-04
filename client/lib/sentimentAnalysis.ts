interface SentimentResult {
  emotion: 'anxiety' | 'fear' | 'frustration' | 'calm' | 'sadness' | 'anger' | 'neutral';
  confidence: number;
  indicators: string[];
  urgency: 'low' | 'moderate' | 'high';
  anxietyLevel: number; // 0-10 scale
}

interface AnxietyIndicators {
  worriedLanguage: string[];
  urgencyIndicators: string[];
  repetitiveQuestions: string[];
  physicalSymptoms: string[];
  emotionalDistress: string[];
}

const ANXIETY_INDICATORS: AnxietyIndicators = {
  worriedLanguage: [
    'worried', 'anxious', 'scared', 'terrified', 'panicked', 'nervous',
    'concerned', 'frightened', 'afraid', 'uneasy', 'apprehensive',
    'distressed', 'alarmed', 'fearful', 'petrified', 'horrified'
  ],
  urgencyIndicators: [
    'immediately', 'right now', 'urgent', 'emergency', 'asap', 'quickly',
    'fast', 'hurry', 'rushing', 'pressing', 'critical', 'severe'
  ],
  repetitiveQuestions: [
    'what if', 'is it serious', 'could it be', 'am i going to',
    'will i', 'should i worry', 'is this bad', 'what happens if'
  ],
  physicalSymptoms: [
    'racing heart', 'chest pain', 'shortness of breath', 'dizzy',
    'lightheaded', 'sweating', 'trembling', 'shaking', 'nausea',
    'butterflies', 'knot in stomach', 'tight chest'
  ],
  emotionalDistress: [
    'overwhelmed', 'helpless', 'hopeless', 'desperate', 'frantic',
    'hysterical', 'panicking', 'losing control', 'breaking down'
  ]
};

const FRUSTRATION_INDICATORS = [
  'frustrated', 'annoyed', 'irritated', 'angry', 'mad', 'upset',
  'disappointed', 'exasperated', 'fed up', 'tired of', 'sick of',
  'bothered', 'aggravated', 'infuriated', 'outraged'
];

const CALM_INDICATORS = [
  'okay', 'fine', 'alright', 'manageable', 'under control',
  'not too bad', 'coping', 'handling it', 'steady', 'stable'
];

const SADNESS_INDICATORS = [
  'sad', 'depressed', 'down', 'unhappy', 'miserable', 'gloomy',
  'heartbroken', 'devastated', 'despair', 'hopeless', 'worthless'
];

export function analyzeSentiment(text: string): SentimentResult {
  const lowerText = text.toLowerCase();
  let anxietyScore = 0;
  let fearScore = 0;
  let frustrationScore = 0;
  let calmScore = 0;
  let sadnessScore = 0;
  let angerScore = 0;

  const indicators: string[] = [];

  // Analyze anxiety indicators
  ANXIETY_INDICATORS.worriedLanguage.forEach(word => {
    if (lowerText.includes(word)) {
      anxietyScore += 2;
      indicators.push(`Anxiety: ${word}`);
    }
  });

  ANXIETY_INDICATORS.urgencyIndicators.forEach(word => {
    if (lowerText.includes(word)) {
      anxietyScore += 1.5;
      fearScore += 1;
      indicators.push(`Urgency: ${word}`);
    }
  });

  ANXIETY_INDICATORS.repetitiveQuestions.forEach(phrase => {
    if (lowerText.includes(phrase)) {
      anxietyScore += 1.5;
      indicators.push(`Repetitive questioning: ${phrase}`);
    }
  });

  ANXIETY_INDICATORS.physicalSymptoms.forEach(symptom => {
    if (lowerText.includes(symptom)) {
      anxietyScore += 2;
      fearScore += 1;
      indicators.push(`Physical anxiety symptom: ${symptom}`);
    }
  });

  ANXIETY_INDICATORS.emotionalDistress.forEach(word => {
    if (lowerText.includes(word)) {
      anxietyScore += 3;
      fearScore += 2;
      indicators.push(`Emotional distress: ${word}`);
    }
  });

  // Analyze frustration
  FRUSTRATION_INDICATORS.forEach(word => {
    if (lowerText.includes(word)) {
      frustrationScore += 2;
      angerScore += 1;
      indicators.push(`Frustration: ${word}`);
    }
  });

  // Analyze calm
  CALM_INDICATORS.forEach(word => {
    if (lowerText.includes(word)) {
      calmScore += 1;
      indicators.push(`Calm: ${word}`);
    }
  });

  // Analyze sadness
  SADNESS_INDICATORS.forEach(word => {
    if (lowerText.includes(word)) {
      sadnessScore += 2;
      indicators.push(`Sadness: ${word}`);
    }
  });

  // Calculate anxiety level (0-10 scale)
  const anxietyLevel = Math.min(10, Math.max(0, anxietyScore / 2));

  // Determine primary emotion
  const scores = {
    anxiety: anxietyScore,
    fear: fearScore,
    frustration: frustrationScore,
    calm: calmScore,
    sadness: sadnessScore,
    anger: angerScore,
    neutral: 0
  };

  const maxScore = Math.max(...Object.values(scores));
  let primaryEmotion: SentimentResult['emotion'] = 'neutral';

  if (maxScore > 0) {
    const emotions = Object.keys(scores) as SentimentResult['emotion'][];
    primaryEmotion = emotions.reduce((a, b) => scores[a] > scores[b] ? a : b);
  }

  // Calculate confidence (0-100)
  const totalIndicators = indicators.length;
  const confidence = Math.min(100, totalIndicators * 15 + (maxScore * 10));

  // Determine urgency level
  let urgency: SentimentResult['urgency'] = 'low';
  if (anxietyLevel >= 7 || fearScore >= 3) {
    urgency = 'high';
  } else if (anxietyLevel >= 4 || fearScore >= 1.5) {
    urgency = 'moderate';
  }

  return {
    emotion: primaryEmotion,
    confidence: Math.round(confidence),
    indicators: indicators.slice(0, 5), // Limit to top 5 indicators
    urgency,
    anxietyLevel: Math.round(anxietyLevel * 10) / 10
  };
}

export function generateEmpatheticResponse(sentiment: SentimentResult, originalResponse: string): string {
  let empatheticPrefix = '';
  let calmingSuffix = '';

  switch (sentiment.emotion) {
    case 'anxiety':
      empatheticPrefix = sentiment.anxietyLevel >= 7
        ? "I can hear how anxious you're feeling right now, and that's completely understandable. Take a deep breath - you're not alone in this. "
        : "I understand this is causing you some anxiety, and that's a normal response. ";

      calmingSuffix = sentiment.urgency === 'high'
        ? "\n\nRemember to breathe slowly - try inhaling for 4 counts, holding for 4, and exhaling for 4. If your anxiety feels overwhelming, please reach out to a healthcare professional or emergency services if needed."
        : "\n\nTry to take a few slow, deep breaths. This can help calm your nervous system while we work through this together.";
      break;

    case 'fear':
      empatheticPrefix = "I can sense how frightening this must be for you. It's okay to feel scared when dealing with health concerns. ";
      calmingSuffix = "\n\nYou're taking a positive step by reaching out for information. We'll address your concerns step by step.";
      break;

    case 'frustration':
      empatheticPrefix = "I understand how frustrating this situation must be. It's completely valid to feel this way. ";
      calmingSuffix = "\n\nLet's work together to find some clarity and solutions that can help.";
      break;

    case 'sadness':
      empatheticPrefix = "I'm sorry you're going through this - it sounds really difficult. ";
      calmingSuffix = "\n\nPlease know that your feelings are valid, and it's okay to ask for support when you need it.";
      break;

    case 'anger':
      empatheticPrefix = "I can hear how upsetting this is for you. It's understandable to feel angry about health challenges. ";
      calmingSuffix = "\n\nLet's focus on what we can do to help you feel more in control of the situation.";
      break;

    case 'calm':
      empatheticPrefix = "It's good to hear you're managing this thoughtfully. ";
      calmingSuffix = "";
      break;

    default:
      empatheticPrefix = "Thank you for sharing how you're feeling. ";
      calmingSuffix = "";
  }

  return empatheticPrefix + originalResponse + calmingSuffix;
}

export function shouldFlagForProfessionalHelp(sentiment: SentimentResult, symptoms: string[]): boolean {
  // Flag if anxiety level is very high
  if (sentiment.anxietyLevel >= 8) return true;

  // Flag if multiple severe anxiety indicators
  if (sentiment.indicators.filter(ind => ind.includes('Emotional distress')).length >= 2) return true;

  // Flag if urgent symptoms are mentioned
  const urgentSymptoms = ['chest pain', 'shortness of breath', 'severe pain', 'unconsciousness', 'bleeding'];
  if (symptoms.some(symptom => urgentSymptoms.some(urgent => symptom.toLowerCase().includes(urgent)))) return true;

  return false;
}