import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate, Link } from "react-router-dom";
import { generateMedicalResponse } from "@/lib/gemini";
import { analyzeSentiment, generateEmpatheticResponse, shouldFlagForProfessionalHelp } from "@/lib/sentimentAnalysis";
import { speakResponse } from "@/lib/voiceUtils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import MainLayout from "@/components/MainLayout";
import BottomNav from "@/components/BottomNav";
import SymptomSelector from "@/components/SymptomSelector";
import FileUpload from "@/components/FileUpload";
import { ProcessedFile } from "@/lib/fileProcessing";
import {
  Send,
  User,
  Bot,
  Loader2,
  AlertTriangle,
  Copy,
  Stethoscope,
  Pill,
  Heart,
  Shield,
  Clock,
  RefreshCw,
  Plus,
  MessageCircle,
  FileText,
  BarChart3,
  Upload,
  Image as ImageIcon,
  Volume2,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Medication {
  name: string;
  dosage: string;
  frequency: string;
  notes?: string;
  type: "over-the-counter";
}

interface Analysis {
  id: string;
  symptoms: string[];
  diagnosis: string;
  severity: "low" | "moderate" | "high";
  recommendations: string[];
  medications: Medication[];
  whenToSeekHelp: string;
  confidence: {
    textAnalysis: number; // 0-100 confidence score for text-based analysis
    imageAnalysis?: number; // 0-100 confidence score for image analysis (optional)
    contextAnalysis?: number; // 0-100 confidence score for health history context
    ensemble: number; // 0-100 combined confidence score
  };
  supportingEvidence: {
    textBased: string[]; // Evidence from symptom text analysis
    imageBased?: string[]; // Evidence from image analysis (optional)
    contextBased?: string[]; // Evidence from health history context
  };
  personalizedInsights?: string[]; // Key insights from patient's health profile
}

interface Message {
  id: string;
  type: "user" | "bot" | "analysis";
  content: string;
  timestamp: Date;
  isTyping?: boolean;
  analysis?: Analysis;
  sentiment?: {
    emotion: 'anxiety' | 'fear' | 'frustration' | 'calm' | 'sadness' | 'anger' | 'neutral';
    confidence: number;
    indicators: string[];
    urgency: 'low' | 'moderate' | 'high';
    anxietyLevel: number;
  };
}

export default function Chat() {
  const { user, loading } = useAuth();
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      type: "bot",
      content:
        "Hello! I'm NINA, your AI medical assistant. Describe your symptoms and I'll provide analysis with treatment recommendations and medication suggestions. You can also upload medical images or reports for more comprehensive analysis.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [showSymptomSelector, setShowSymptomSelector] = useState(false);
  const [showFileUpload, setShowFileUpload] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<ProcessedFile | null>(null);
  const [uploadedImage, setUploadedImage] = useState<File | null>(null);
  const [showAnalysis, setShowAnalysis] = useState(false);
  const [currentSentiment, setCurrentSentiment] = useState<{
    emotion: 'anxiety' | 'fear' | 'frustration' | 'calm' | 'sadness' | 'anger' | 'neutral';
    confidence: number;
    indicators: string[];
    urgency: 'low' | 'moderate' | 'high';
    anxietyLevel: number;
  } | null>(null);
  const [showAnxietySupport, setShowAnxietySupport] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const handleSendMessage = async () => {
    if (!input.trim() || isTyping) return;

    // Analyze sentiment of user input
    const sentiment = analyzeSentiment(input);
    setCurrentSentiment(sentiment);

    const userMessage: Message = {
      id: Date.now().toString(),
      type: "user",
      content: input,
      timestamp: new Date(),
      sentiment: sentiment,
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsTyping(true);

    // Add typing indicator
    const typingMessage: Message = {
      id: (Date.now() + 1).toString(),
      type: "bot",
      content: "",
      timestamp: new Date(),
      isTyping: true,
    };
    setMessages((prev) => [...prev, typingMessage]);

    try {
      // Fetch user's health history for context
      let healthHistoryContext = "";
      try {
        const response = await fetch('/api/health-profile', {
          headers: {
            'Authorization': `Bearer ${user?.id}` // Assuming auth token is available
          }
        });
        if (response.ok) {
          const profile = await response.json();
          if (profile.data) {
            healthHistoryContext = `

PATIENT HEALTH HISTORY CONTEXT:
- Age: ${profile.data.date_of_birth ? new Date().getFullYear() - new Date(profile.data.date_of_birth).getFullYear() : 'Not specified'}
- Gender: ${profile.data.gender || 'Not specified'}
- Blood Type: ${profile.data.blood_type || 'Not specified'}
- Allergies: ${profile.data.allergies?.join(', ') || 'None specified'}
- Current Medications: ${profile.data.medications?.join(', ') || 'None specified'}
- Chronic Conditions: ${profile.data.chronic_conditions?.join(', ') || 'None specified'}
- Family History: ${profile.data.family_history ? JSON.stringify(profile.data.family_history) : 'Not specified'}
- Smoking Status: ${profile.data.smoking_status || 'Not specified'}
- Alcohol Consumption: ${profile.data.alcohol_consumption || 'Not specified'}
- Exercise Frequency: ${profile.data.exercise_frequency || 'Not specified'}`;
          }
        }
      } catch (error) {
        console.log('Could not fetch health profile for context:', error);
      }

      // Fetch recent medical history
      let medicalHistoryContext = "";
      try {
        const response = await fetch('/api/medical-history?status=active', {
          headers: {
            'Authorization': `Bearer ${user?.id}`
          }
        });
        if (response.ok) {
          const history = await response.json();
          if (history.data && history.data.length > 0) {
            medicalHistoryContext = `

RECENT MEDICAL HISTORY:
${history.data.slice(0, 5).map((record: any) =>
  `- ${record.condition_name} (diagnosed: ${new Date(record.diagnosis_date).toLocaleDateString()}, status: ${record.status})`
).join('\n')}`;
          }
        }
      } catch (error) {
        console.log('Could not fetch medical history for context:', error);
      }

      // Fetch recent vital signs
      let vitalSignsContext = "";
      try {
        const response = await fetch('/api/vital-signs/latest/summary', {
          headers: {
            'Authorization': `Bearer ${user?.id}`
          }
        });
        if (response.ok) {
          const vitals = await response.json();
          if (vitals.data) {
            vitalSignsContext = `

RECENT VITAL SIGNS:
- Blood Pressure: ${vitals.data.systolic_bp || 'N/A'}/${vitals.data.diastolic_bp || 'N/A'} mmHg (${new Date(vitals.data.measurement_date).toLocaleDateString()})
- Heart Rate: ${vitals.data.heart_rate || 'N/A'} bpm
- Temperature: ${vitals.data.temperature || 'N/A'}°${vitals.data.temperature_unit || 'C'}
- Weight: ${vitals.data.weight || 'N/A'} ${vitals.data.weight_unit || 'kg'}
- BMI: ${vitals.data.bmi || 'N/A'}
- Blood Glucose: ${vitals.data.blood_glucose || 'N/A'} ${vitals.data.blood_glucose_unit || 'mg/dL'}`;
          }
        }
      } catch (error) {
        console.log('Could not fetch vital signs for context:', error);
      }

      let prompt = `
You are NINA, a caring and knowledgeable medical AI assistant with access to the patient's comprehensive health history. Analyze these symptoms: "${input}"${healthHistoryContext}${medicalHistoryContext}${vitalSignsContext}`;

      if (uploadedFile) {
        prompt += `

Additionally, analyze this medical document that was uploaded:
Document Type: ${uploadedFile.fileType.toUpperCase()}
Document Name: ${uploadedFile.fileName}
Extracted Content:
${uploadedFile.text}

Please incorporate insights from this document into your analysis.`;
      }

      prompt += `

You are performing CONTEXT-AWARE MULTI-MODAL ANALYSIS with full access to the patient's health history, medical records, and vital signs.

ANALYSIS REQUIREMENTS:
1. Consider the patient's complete health context including demographics, medical history, allergies, current medications, and vital signs
2. Perform separate analysis of symptom text and image/document data
3. Calculate confidence scores for each modality (0-100)
4. Factor in correlations between current symptoms and past medical conditions
5. Check for medication interactions and contraindications based on patient history
6. Provide personalized recommendations considering the patient's health profile
7. Combine results using ensemble logic: weighted average based on data quality and relevance

CONTEXT-AWARE ANALYSIS GUIDELINES:
- Review allergies and avoid recommending medications that could cause reactions
- Consider chronic conditions and how they might influence current symptoms
- Check medication history for potential interactions with new recommendations
- Factor in vital signs trends and how they relate to current symptoms
- Consider family history for genetic predispositions
- Adjust severity assessment based on patient's medical background

CONFIDENCE SCORING GUIDELINES:
- Text Analysis: Base on symptom specificity, duration, severity details, and correlation with patient history (75-98 range)
- Image Analysis: Base on image clarity, medical relevance, visible test results (65-92 range)
- Context Integration: Bonus confidence for strong correlations with patient history (+5-15 points)
- Ensemble: Weighted combination: (textAnalysis * 0.5) + (imageAnalysis * 0.3) + (contextAnalysis * 0.2)

Provide a human-like, conversational response that includes:
1. A brief, warm acknowledgment of their symptoms considering their health history
2. The most likely diagnosis/conditions based on symptoms, medical history, and available data
3. Specific treatment recommendations and medications (checking for allergies/interactions)
4. Personalized advice based on their health profile and vital signs
5. 1-2 thoughtful follow-up questions to gather more details for better accuracy

Write in a natural, conversational tone as if you're a knowledgeable healthcare provider speaking directly to the patient. Be empathetic but professional, and reference their health history when relevant.

Provide your response in this JSON format:
{
  "humanResponse": "A natural, conversational response that acknowledges their symptoms, considers their health history, provides likely diagnosis, gives personalized treatment recommendations, and asks 1-2 specific follow-up questions",
  "symptoms": ["symptom1", "symptom2"],
  "diagnosis": "Primary diagnosis or 2-3 most likely conditions, considering patient history",
  "severity": "low|moderate|high",
  "recommendations": ["recommendation1", "recommendation2"],
  "medications": [
    {
      "name": "Medication name (checked for allergies/interactions)",
      "dosage": "Recommended dosage",
      "frequency": "How often to take",
      "notes": "Important notes including any allergy considerations",
      "type": "over-the-counter"
    }
  ],
  "whenToSeekHelp": "When to seek immediate medical attention, considering patient history",
  "confidence": {
    "textAnalysis": 85,
    "imageAnalysis": 78,
    "contextAnalysis": 92,
    "ensemble": 85
  },
  "supportingEvidence": {
    "textBased": ["Evidence from symptom description", "Duration and intensity factors"],
    "imageBased": ["Visual indicators from uploaded image", "Test results visible in image"],
    "contextBased": ["Correlations with medical history", "Vital signs considerations", "Medication interaction checks"]
  },
  "personalizedInsights": ["Key insights from patient's health profile", "History correlations", "Personalized risk factors"]
}

Make the humanResponse sound natural and caring, without excessive medical jargon. Focus on being helpful and reassuring while providing accurate, personalized information based on their complete health context.
      `;

      const rawResponse = await generateMedicalResponse(prompt, [], 2, uploadedFile?.text, uploadedImage || undefined);
      let response = cleanResponse(rawResponse);

      // Generate empathetic response based on sentiment
      if (sentiment.emotion !== 'neutral' && sentiment.emotion !== 'calm') {
        response = generateEmpatheticResponse(sentiment, response);
      }

      // Check if professional help should be flagged
      const shouldFlagHelp = shouldFlagForProfessionalHelp(sentiment, []);

      // Try to parse JSON response
      let analysis: Analysis | null = null;
      let humanResponse = "";

      try {
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsedData = JSON.parse(jsonMatch[0]);

          // Extract human response
          humanResponse = parsedData.humanResponse || "";

          // Create analysis object
          if (parsedData.diagnosis) {
            // Calculate ensemble confidence based on available modalities
            let ensembleConfidence = 0;
            const textConf = parsedData.confidence?.textAnalysis || 75;
            const imageConf = parsedData.confidence?.imageAnalysis;
            const contextConf = parsedData.confidence?.contextAnalysis;

            if (contextConf && imageConf) {
              // All modalities: weighted average
              ensembleConfidence = Math.round(textConf * 0.5 + imageConf * 0.3 + contextConf * 0.2);
            } else if (contextConf && !imageConf) {
              // Text and context only
              ensembleConfidence = Math.round(textConf * 0.7 + contextConf * 0.3);
            } else if (uploadedImage && imageConf) {
              // Text and image only
              ensembleConfidence = Math.round(textConf * 0.6 + imageConf * 0.4);
            } else if (uploadedImage && imageConf) {
              // Image only
              ensembleConfidence = imageConf;
            } else {
              // Text only
              ensembleConfidence = textConf;
            }

            analysis = {
              id: Date.now().toString(),
              symptoms: parsedData.symptoms || [],
              diagnosis: parsedData.diagnosis || "",
              severity: parsedData.severity || "moderate",
              recommendations: parsedData.recommendations || [],
              medications: parsedData.medications || [],
              whenToSeekHelp: parsedData.whenToSeekHelp || "",
              confidence: {
                textAnalysis: textConf,
                imageAnalysis: imageConf,
                contextAnalysis: contextConf,
                ensemble: ensembleConfidence,
              },
              supportingEvidence: {
                textBased: parsedData.supportingEvidence?.textBased || [],
                imageBased: parsedData.supportingEvidence?.imageBased,
                contextBased: parsedData.supportingEvidence?.contextBased,
              },
              personalizedInsights: parsedData.personalizedInsights,
            };
          }
        }
      } catch (parseError) {
        console.error("Failed to parse analysis:", parseError);
      }

      // Use empathetic response if we have one
      const finalResponse = humanResponse || response;

      // Speak response if voice is enabled
      if (finalResponse) {
        speakResponse(finalResponse).catch(console.error);
      }

      setMessages((prev) => {
        const newMessages = prev.filter((msg) => !msg.isTyping);

        // Always show human response first
        const messages = [
          ...newMessages,
          {
            id: (Date.now() + 2).toString(),
            type: "bot" as const,
            content: finalResponse,
            timestamp: new Date(),
          },
        ];

        // Add professional help flag if needed
        if (shouldFlagHelp) {
          messages.push({
            id: (Date.now() + 4).toString(),
            type: "bot" as const,
            content: "I notice you're experiencing significant anxiety. While I can provide information and support, I strongly recommend speaking with a mental health professional for personalized care. Would you like me to help you find resources?",
            timestamp: new Date(),
          });
        }

        // Add structured analysis if available
        if (analysis) {
          messages.push({
            id: (Date.now() + 3).toString(),
            type: "analysis" as const,
            content: "Here's a detailed breakdown:",
            timestamp: new Date(),
            analysis: analysis,
          });
          // Auto-show analysis for progressive disclosure
          setShowAnalysis(true);
        }

        return messages;
      });
    } catch (error: any) {
      console.error("Chat error:", error);

      let errorMessage =
        "I apologize, but I'm having trouble analyzing your symptoms right now. Please try again or consult with a healthcare professional.";

      // Handle file processing errors
      if (error?.code === 'FILE_TOO_LARGE') {
        errorMessage = "The uploaded file is too large. Please upload a file smaller than 10MB.";
      } else if (error?.code === 'INVALID_FILE_TYPE') {
        errorMessage = "Please upload a valid PDF or image file (JPEG, PNG, WebP, BMP).";
      } else if (error?.code === 'PDF_EXTRACTION_FAILED') {
        errorMessage = "I couldn't read the PDF file. Please ensure it's not password-protected and try again.";
      } else if (error?.code === 'OCR_EXTRACTION_FAILED') {
        errorMessage = "I couldn't extract text from the image. Please ensure the image is clear and contains readable text.";
      } else if (error?.code === 'NO_TEXT_FOUND') {
        errorMessage = "No readable text was found in the uploaded file. Please check the file and try again.";
      } else if (error?.code === 'IMAGE_ANALYSIS_FAILED') {
        errorMessage = "I couldn't analyze the uploaded image. Please ensure the image is clear and try again.";
      }

      // Provide more specific error messages for API issues
      if (error?.message?.includes("[503]")) {
        errorMessage =
          "I'm currently experiencing high demand and can't process your request right now. Please try again in a few minutes - the service should be back to normal shortly.";
      } else if (error?.message?.includes("[429]")) {
        errorMessage =
          "I'm receiving too many requests right now. Please wait a moment and try again.";
      } else if (
        error?.message?.includes("network") ||
        error?.message?.includes("fetch")
      ) {
        errorMessage =
          "There seems to be a connection issue. Please check your internet connection and try again.";
      }

      setMessages((prev) => {
        const newMessages = prev.filter((msg) => !msg.isTyping);
        return [
          ...newMessages,
          {
            id: (Date.now() + 3).toString(),
            type: "bot",
            content: errorMessage,
            timestamp: new Date(),
          },
        ];
      });
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleSymptomSelect = (symptoms: string[]) => {
    const symptomText = `I'm experiencing: ${symptoms.join(", ")}`;
    setInput(symptomText);
    setShowSymptomSelector(false);
  };

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content);
  };

  const cleanResponse = (response: string): string => {
    // Remove repetitive disclaimer text
    const disclaimersToRemove = [
      "Once you provide more details, I can offer general information about possible causes and suggest some general self-care measures. Remember, it's crucial to consult a healthcare professional for a proper diagnosis and treatment plan, especially given the duration of your symptoms.",
      "Please consult with a healthcare professional for proper diagnosis and treatment.",
      "It's important to consult with a healthcare professional for a proper diagnosis.",
      "Remember to consult a healthcare professional for proper medical advice.",
      "This information is for educational purposes only.",
      "Please seek professional medical advice.",
    ];

    let cleanedResponse = response;

    // Remove markdown formatting that shows up as **text**
    cleanedResponse = cleanedResponse.replace(/\*\*(.*?)\*\*/g, "$1");
    cleanedResponse = cleanedResponse.replace(/\*(.*?)\*/g, "$1");

    // Remove disclaimers
    disclaimersToRemove.forEach((disclaimer) => {
      cleanedResponse = cleanedResponse.replace(disclaimer, "");
    });

    // Clean up any resulting double spaces or excessive line breaks
    cleanedResponse = cleanedResponse.replace(/\s+/g, " ").trim();

    return cleanedResponse;
  };

  const handleNewChat = () => {
    setMessages([
      {
        id: "1",
        type: "bot",
        content:
          "Hello! I'm NINA, your AI medical assistant. Describe your symptoms and I'll provide analysis with treatment recommendations and medication suggestions. You can also upload medical images or reports for more comprehensive analysis.",
        timestamp: new Date(),
      },
    ]);
    setInput("");
    setIsTyping(false);
    setShowSymptomSelector(false);
    setShowFileUpload(false);
    setUploadedFile(null);
    setUploadedImage(null);
    setShowAnalysis(false);
    setCurrentSentiment(null);
  };


  const handleFileProcessed = (processedFile: ProcessedFile) => {
    setUploadedFile(processedFile);
    setShowFileUpload(false);
  };

  const handleImageProcessed = (imageFile: File) => {
    setUploadedImage(imageFile);
    setShowFileUpload(false);
  };

  const handleFileError = (error: string) => {
    console.error("File processing error:", error);
    // Error is already displayed in the FileUpload component
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
      case "moderate":
        return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
      case "high":
        return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200";
    }
  };

  const getMedicationType = (type: string) => {
    return {
      label: "OTC",
      color:
        "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
    };
  };

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Fixed Header - Chat specific (blue bar with Nina centered) */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-blue-400 shadow-sm">
        <div className="h-16 flex items-center justify-center">
          <h1 className="text-xl font-semibold text-white">NINA</h1>
        </div>
      </nav>

      {/* Symptom Selector Overlay */}
      {showSymptomSelector && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 sm:p-6 z-50">
          <SymptomSelector
            onSymptomSelect={handleSymptomSelect}
            onClose={() => setShowSymptomSelector(false)}
          />
        </div>
      )}

      {/* File Upload Overlay */}
      {showFileUpload && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 sm:p-6 z-50">
          <div className="bg-background rounded-lg p-4 sm:p-6 w-full max-w-sm sm:max-w-md max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base sm:text-lg font-semibold">Upload Medical Report</h3>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowFileUpload(false)}
                className="h-8 w-8 p-0"
              >
                ×
              </Button>
            </div>
            <FileUpload
              onFileProcessed={handleFileProcessed}
              onImageProcessed={handleImageProcessed}
              onError={handleFileError}
              disabled={isTyping}
            />
          </div>
        </div>
      )}



      {/* Messages - Scrollable content between fixed header and input */}
      <div
        className={cn(
          "flex-1 overflow-y-auto px-4 sm:px-6 py-4 sm:py-6 space-y-4 sm:space-y-6 bg-background transition-all duration-300"
        )}
        style={{
          marginTop: '64px',
          marginBottom: '120px'
        }}
      >
        {messages.map((message) => (
          <div key={message.id}>
            {message.type === "analysis" && showAnalysis ? (
              // Analysis Display
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <div className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 shadow-md bg-blue-400">
                    <Bot className="w-4 h-4 text-white" />
                  </div>
                  <div className="flex-1">
                    <p className="text-sm text-muted-foreground mb-4">
                      {message.content}
                    </p>

                    {message.analysis && (
                      <div className="space-y-4">
                        {/* Diagnosis & Severity */}
                        <Card>
                          <CardContent className="p-4">
                            <div className="flex items-center justify-between mb-3">
                              <h3 className="font-semibold flex items-center space-x-2">
                                <Stethoscope className="w-4 h-4" />
                                <span>Diagnosis</span>
                              </h3>
                              <div className="flex items-center space-x-2">
                                <Badge
                                  className={getSeverityColor(
                                    message.analysis.severity,
                                  )}
                                >
                                  {message.analysis.severity.toUpperCase()} RISK
                                </Badge>
                                <Badge
                                  variant="outline"
                                  className="bg-blue-50 text-blue-700 border-blue-200"
                                >
                                  {message.analysis.confidence.ensemble}% Confidence
                                </Badge>
                              </div>
                            </div>
                            <p className="text-muted-foreground">
                              {message.analysis.diagnosis}
                            </p>
                          </CardContent>
                        </Card>

                        {/* Symptoms */}
                        <Card>
                          <CardContent className="p-4">
                            <h3 className="font-semibold mb-3 flex items-center space-x-2">
                              <Heart className="w-4 h-4" />
                              <span>Identified Symptoms</span>
                            </h3>
                            <div className="flex flex-wrap gap-2">
                              {message.analysis.symptoms.map(
                                (symptom, index) => (
                                  <Badge key={index} variant="outline">
                                    {symptom}
                                  </Badge>
                                ),
                              )}
                            </div>
                          </CardContent>
                        </Card>

                        {/* Medications */}
                        {message.analysis.medications.length > 0 && (
                          <Card>
                            <CardContent className="p-4">
                              <h3 className="font-semibold mb-3 flex items-center space-x-2">
                                <Pill className="w-4 h-4" />
                                <span>Recommended Medications</span>
                              </h3>
                              <div className="space-y-3">
                                {message.analysis.medications.map(
                                  (med, index) => (
                                    <div
                                      key={index}
                                      className="border rounded-lg p-3 bg-muted/50"
                                    >
                                      <div className="flex items-center justify-between mb-2">
                                        <h4 className="font-medium">
                                          {med.name}
                                        </h4>
                                        <Badge
                                          className={
                                            getMedicationType(med.type).color
                                          }
                                        >
                                          {getMedicationType(med.type).label}
                                        </Badge>
                                      </div>
                                      <div className="grid grid-cols-2 gap-2 text-sm text-muted-foreground">
                                        <p>
                                          <strong>Dosage:</strong>{" "}
                                          {med.dosage}
                                        </p>
                                        <p>
                                          <strong>Frequency:</strong>{" "}
                                          {med.frequency}
                                        </p>
                                      </div>
                                      {med.notes && (
                                        <p className="text-xs text-muted-foreground mt-2">
                                          <strong>Note:</strong> {med.notes}
                                        </p>
                                      )}
                                    </div>
                                  ),
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* Recommendations */}
                        <Card>
                          <CardContent className="p-4">
                            <h3 className="font-semibold mb-3 flex items-center space-x-2">
                              <Shield className="w-4 h-4" />
                              <span>Recommendations</span>
                            </h3>
                            <ul className="space-y-2">
                              {message.analysis.recommendations.map(
                                (rec, index) => (
                                  <li
                                    key={index}
                                    className="flex items-start space-x-2"
                                  >
                                    <div className="w-1.5 h-1.5 bg-primary rounded-full mt-2 flex-shrink-0"></div>
                                    <span className="text-sm text-muted-foreground">
                                      {rec}
                                    </span>
                                  </li>
                                ),
                              )}
                            </ul>
                          </CardContent>
                        </Card>

                        {/* Supporting Evidence */}
                        {(message.analysis.supportingEvidence.textBased.length > 0 ||
                          message.analysis.supportingEvidence.imageBased?.length ||
                          message.analysis.supportingEvidence.contextBased?.length) && (
                          <Card>
                            <CardContent className="p-4">
                              <h3 className="font-semibold mb-3 flex items-center space-x-2">
                                <Shield className="w-4 h-4" />
                                <span>Supporting Evidence</span>
                              </h3>
                              <div className="space-y-3">
                                {message.analysis.supportingEvidence.textBased.length > 0 && (
                                  <div>
                                    <h4 className="text-sm font-medium text-blue-700 dark:text-blue-300 mb-2">
                                      From Symptom Analysis ({message.analysis.confidence.textAnalysis}% confidence)
                                    </h4>
                                    <ul className="space-y-1">
                                      {message.analysis.supportingEvidence.textBased.map((evidence, index) => (
                                        <li key={index} className="flex items-start space-x-2 text-sm">
                                          <div className="w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
                                          <span className="text-muted-foreground">{evidence}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {message.analysis.supportingEvidence.imageBased?.length > 0 && (
                                  <div>
                                    <h4 className="text-sm font-medium text-green-700 dark:text-green-300 mb-2">
                                      From Image Analysis ({message.analysis.confidence.imageAnalysis}% confidence)
                                    </h4>
                                    <ul className="space-y-1">
                                      {message.analysis.supportingEvidence.imageBased.map((evidence, index) => (
                                        <li key={index} className="flex items-start space-x-2 text-sm">
                                          <div className="w-1.5 h-1.5 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
                                          <span className="text-muted-foreground">{evidence}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {message.analysis.supportingEvidence.contextBased?.length > 0 && (
                                  <div>
                                    <h4 className="text-sm font-medium text-purple-700 dark:text-purple-300 mb-2">
                                      From Health History Context ({message.analysis.confidence.contextAnalysis}% confidence)
                                    </h4>
                                    <ul className="space-y-1">
                                      {message.analysis.supportingEvidence.contextBased.map((evidence, index) => (
                                        <li key={index} className="flex items-start space-x-2 text-sm">
                                          <div className="w-1.5 h-1.5 bg-purple-500 rounded-full mt-2 flex-shrink-0"></div>
                                          <span className="text-muted-foreground">{evidence}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* Personalized Insights */}
                        {message.analysis.personalizedInsights && message.analysis.personalizedInsights.length > 0 && (
                          <Card className="border-purple-200 bg-purple-50 dark:bg-purple-950 dark:border-purple-800">
                            <CardContent className="p-4">
                              <h3 className="font-semibold mb-3 flex items-center space-x-2 text-purple-800 dark:text-purple-200">
                                <Heart className="w-4 h-4" />
                                <span>Personalized Health Insights</span>
                              </h3>
                              <ul className="space-y-2">
                                {message.analysis.personalizedInsights.map((insight, index) => (
                                  <li key={index} className="flex items-start space-x-2">
                                    <div className="w-1.5 h-1.5 bg-purple-500 rounded-full mt-2 flex-shrink-0"></div>
                                    <span className="text-sm text-purple-700 dark:text-purple-300">{insight}</span>
                                  </li>
                                ))}
                              </ul>
                            </CardContent>
                          </Card>
                        )}

                        {/* When to Seek Help */}
                        <Card className="border-orange-200 bg-orange-50 dark:bg-orange-950 dark:border-orange-800">
                          <CardContent className="p-4">
                            <h3 className="font-semibold mb-3 flex items-center space-x-2 text-orange-800 dark:text-orange-200">
                              <Clock className="w-4 h-4" />
                              <span>When to Seek Medical Help</span>
                            </h3>
                            <p className="text-sm text-orange-700 dark:text-orange-300">
                              {message.analysis.whenToSeekHelp}
                            </p>
                          </CardContent>
                        </Card>
                      </div>
                    )}

                    <p className="text-xs text-muted-foreground mt-4">
                      {message.timestamp.toLocaleDateString("en-GB", {
                        day: "2-digit",
                        month: "2-digit",
                      })}{" "}
                      {message.timestamp.toLocaleTimeString("en-GB", {
                        hour: "2-digit",
                        minute: "2-digit",
                        hour12: false,
                      })}
                    </p>
                  </div>
                </div>
              </div>
            ) : (
              // Regular Message Display
              <div
                className={cn(
                  "flex items-start space-x-3 group",
                  message.type === "user"
                    ? "flex-row-reverse space-x-reverse"
                    : "",
                )}
              >
                {/* Progressive Disclosure Toggle for Analysis */}
                {message.type === "bot" && messages.some(m => m.type === "analysis") && !showAnalysis && (
                  <div className="w-full mb-4">
                    <Button
                      onClick={() => setShowAnalysis(true)}
                      variant="outline"
                      className="w-full bg-blue-50 hover:bg-blue-100 border-blue-200 text-blue-700 hover:text-blue-800 transition-all duration-300"
                    >
                      <BarChart3 className="w-4 h-4 mr-2" />
                      View Detailed Analysis & Confidence Scores
                    </Button>
                  </div>
                )}
                <div
                  className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 shadow-md",
                    message.type === "user"
                      ? "bg-blue-400"
                      : "bg-blue-400",
                  )}
                >
                  {message.type === "user" ? (
                    <User className="w-4 h-4 text-white" />
                  ) : (
                    <Bot className="w-4 h-4 text-white" />
                  )}
                </div>

                <div
                  className={cn(
                    "max-w-[85%] sm:max-w-[75%] rounded-2xl px-3 sm:px-4 py-2 sm:py-3 shadow-sm",
                    message.type === "user"
                      ? "bg-blue-400 text-white"
                      : "bg-muted text-muted-foreground",
                  )}
                  role={message.type === "bot" ? "region" : undefined}
                  aria-label={message.type === "bot" ? "AI response" : undefined}
                >
                  {message.isTyping ? (
                    <div className="flex items-center space-x-1">
                      <div className="flex space-x-1">
                        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce"></div>
                        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce delay-100"></div>
                        <div className="w-2 h-2 bg-muted-foreground rounded-full animate-bounce delay-200"></div>
                      </div>
                      <span className="text-xs text-muted-foreground ml-2">
                        Analyzing symptoms...
                      </span>
                    </div>
                  ) : (
                    <>
                      <p className="whitespace-pre-wrap leading-relaxed">
                        {message.content}
                      </p>
                      <div className="flex items-center justify-between mt-3">
                        <p
                          className={cn(
                            "text-xs",
                            message.type === "user"
                              ? "text-white/70"
                              : "text-muted-foreground",
                          )}
                        >
                          {message.timestamp.toLocaleDateString("en-GB", {
                            day: "2-digit",
                            month: "2-digit",
                          })}{" "}
                          {message.timestamp.toLocaleTimeString("en-GB", {
                            hour: "2-digit",
                            minute: "2-digit",
                            hour12: false,
                          })}
                        </p>
                        {message.type === "bot" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyMessage(message.content)}
                            className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity duration-200"
                          >
                            <Copy className="w-3 h-3" />
                          </Button>
                        )}
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Fixed Input Section */}
      <div className="fixed bottom-16 left-0 right-0 z-40 border-t border-border/50 bg-background backdrop-blur-lg p-3 sm:p-4 shadow-lg">
        {/* Uploaded File Indicator */}
        {(uploadedFile || uploadedImage) && (
          <div className="mb-3 p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                {uploadedFile ? (
                  <>
                    <FileText className="w-4 h-4 text-blue-600" />
                    <span className="text-sm font-medium text-blue-800 dark:text-blue-200">
                      {uploadedFile.fileName}
                    </span>
                    <Badge variant="outline" className="text-xs">
                      {uploadedFile.fileType.toUpperCase()}
                    </Badge>
                    <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                      Multi-modal Analysis Enabled
                    </Badge>
                  </>
                ) : uploadedImage ? (
                  <>
                    <ImageIcon className="w-4 h-4 text-blue-600" />
                    <span className="text-sm font-medium text-blue-800 dark:text-blue-200">
                      {uploadedImage.name}
                    </span>
                    <Badge variant="outline" className="text-xs">
                      IMAGE
                    </Badge>
                    <Badge variant="outline" className="text-xs bg-green-50 text-green-700 border-green-200">
                      Multi-modal Analysis Enabled
                    </Badge>
                  </>
                ) : null}
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setUploadedFile(null);
                  setUploadedImage(null);
                }}
                className="h-6 w-6 p-0 text-blue-600 hover:text-blue-800"
              >
                ×
              </Button>
            </div>
          </div>
        )}

        <div className="mb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 sm:gap-3">
           <div className="flex flex-col sm:flex-row items-stretch sm:items-center space-y-2 sm:space-y-0 sm:space-x-2">
             <Button
               variant="outline"
               size="sm"
               onClick={() => setShowSymptomSelector(true)}
               className="flex items-center justify-center space-x-2 hover:bg-blue-50 transition-colors duration-200 text-xs sm:text-sm"
             >
               <Stethoscope className="w-4 h-4" />
               <span className="hidden sm:inline">Quick Symptom Selector</span>
               <span className="sm:hidden">Symptoms</span>
             </Button>
             <Button
               variant="outline"
               size="sm"
               onClick={() => setShowFileUpload(true)}
               className="flex items-center justify-center space-x-2 hover:bg-blue-50 transition-colors duration-200 text-xs sm:text-sm"
               disabled={isTyping}
             >
               <Upload className="w-4 h-4" />
               <span className="hidden sm:inline">Upload Report</span>
               <span className="sm:hidden">Upload</span>
             </Button>
           </div>
           <Button
             variant="outline"
             size="sm"
             onClick={handleNewChat}
             className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground hover:bg-blue-50 transition-colors duration-200 self-end sm:self-auto"
             title="New Chat"
           >
             <Plus className="w-4 h-4" />
           </Button>
         </div>
        <div className="flex items-end space-x-2 sm:space-x-4">
          <div className="flex-1 relative">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Describe your symptoms..."
              className="min-h-[44px] sm:min-h-[48px] resize-none rounded-xl border-2 focus:border-blue-400 transition-all duration-300 bg-background shadow-sm text-sm sm:text-base"
              disabled={isTyping}
              aria-label="Type your symptoms or health question"
            />
          </div>
          <Button
            onClick={handleSendMessage}
            disabled={!input.trim() || isTyping}
            className="h-[44px] w-[44px] sm:h-[48px] sm:w-[48px] p-0 rounded-xl bg-blue-400 hover:bg-blue-500 shadow-lg hover:shadow-xl transition-all duration-300 group disabled:opacity-50"
            aria-label={isTyping ? "Processing your message" : "Send message"}
          >
            {isTyping ? (
              <Loader2 className="w-4 h-4 animate-spin text-white" aria-hidden="true" />
            ) : (
              <Send className="w-4 h-4 text-white group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform duration-300" aria-hidden="true" />
            )}
          </Button>
        </div>
        <div className="mt-2 sm:mt-3 flex items-center space-x-2 text-xs text-muted-foreground">
          <AlertTriangle className="w-3 h-3 flex-shrink-0" />
          <span className="text-xs sm:text-sm">
            This is for informational purposes only. Always consult healthcare
            professionals for medical advice.
          </span>
        </div>
      </div>

      {/* Bottom Navigation */}
      <BottomNav />
    </div>
  );
}
