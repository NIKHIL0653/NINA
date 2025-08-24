import { useState, useRef, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate, Link } from "react-router-dom";
import { generateMedicalResponse } from "@/lib/gemini";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import MainLayout from "@/components/MainLayout";
import BottomNav from "@/components/BottomNav";
import SymptomSelector from "@/components/SymptomSelector";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

interface Medication {
  name: string;
  dosage: string;
  frequency: string;
  notes?: string;
  type: "over-the-counter" | "prescription";
}

interface Analysis {
  id: string;
  symptoms: string[];
  diagnosis: string;
  severity: "low" | "moderate" | "high";
  recommendations: string[];
  medications: Medication[];
  whenToSeekHelp: string;
}

interface Message {
  id: string;
  type: "user" | "bot" | "analysis";
  content: string;
  timestamp: Date;
  isTyping?: boolean;
  analysis?: Analysis;
}

export default function Chat() {
  const { user, loading } = useAuth();
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      type: "bot",
      content:
        "Hello! I'm NINA, your AI medical assistant. Describe your symptoms and I'll provide analysis with treatment recommendations and medication suggestions.",
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [showSymptomSelector, setShowSymptomSelector] = useState(false);
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

    const userMessage: Message = {
      id: Date.now().toString(),
      type: "user",
      content: input,
      timestamp: new Date(),
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
      const prompt = `
You are NINA, a caring and knowledgeable medical AI assistant. Analyze these symptoms: "${input}"

Provide a human-like, conversational response that includes:
1. A brief, warm acknowledgment of their symptoms
2. The most likely diagnosis/conditions based on symptoms
3. Specific treatment recommendations and medications
4. 1-2 thoughtful follow-up questions to gather more details for better accuracy

Write in a natural, conversational tone as if you're a knowledgeable healthcare provider speaking directly to the patient. Be empathetic but professional.

Provide your response in this JSON format:
{
  "humanResponse": "A natural, conversational response that acknowledges their symptoms, provides likely diagnosis, gives treatment recommendations, and asks 1-2 specific follow-up questions",
  "symptoms": ["symptom1", "symptom2"],
  "diagnosis": "Primary diagnosis or 2-3 most likely conditions",
  "severity": "low|moderate|high",
  "recommendations": ["recommendation1", "recommendation2"],
  "medications": [
    {
      "name": "Medication name",
      "dosage": "Recommended dosage",
      "frequency": "How often to take",
      "notes": "Important notes",
      "type": "over-the-counter|prescription"
    }
  ],
  "whenToSeekHelp": "When to seek immediate medical attention"
}

Make the humanResponse sound natural and caring, without excessive medical jargon. Focus on being helpful and reassuring while providing accurate information.
      `;

      const rawResponse = await generateMedicalResponse(prompt, []);
      const response = cleanResponse(rawResponse);

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
            analysis = {
              id: Date.now().toString(),
              symptoms: parsedData.symptoms || [],
              diagnosis: parsedData.diagnosis || "",
              severity: parsedData.severity || "moderate",
              recommendations: parsedData.recommendations || [],
              medications: parsedData.medications || [],
              whenToSeekHelp: parsedData.whenToSeekHelp || "",
            };
          }
        }
      } catch (parseError) {
        console.error("Failed to parse analysis:", parseError);
      }

      setMessages((prev) => {
        const newMessages = prev.filter((msg) => !msg.isTyping);

        // Always show human response first
        const messages = [
          ...newMessages,
          {
            id: (Date.now() + 2).toString(),
            type: "bot" as const,
            content: humanResponse || cleanResponse(response),
            timestamp: new Date(),
          },
        ];

        // Add structured analysis if available
        if (analysis) {
          messages.push({
            id: (Date.now() + 3).toString(),
            type: "analysis" as const,
            content: "Here's a detailed breakdown:",
            timestamp: new Date(),
            analysis: analysis,
          });
        }

        return messages;
      });
    } catch (error: any) {
      console.error("Chat error:", error);

      let errorMessage =
        "I apologize, but I'm having trouble analyzing your symptoms right now. Please try again or consult with a healthcare professional.";

      // Provide more specific error messages
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
          "Hello! I'm NINA, your AI medical assistant. Describe your symptoms and I'll provide analysis with treatment recommendations and medication suggestions.",
        timestamp: new Date(),
      },
    ]);
    setInput("");
    setIsTyping(false);
    setShowSymptomSelector(false);
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
    return type === "over-the-counter"
      ? {
          label: "OTC",
          color:
            "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
        }
      : {
          label: "Rx",
          color:
            "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
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
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-6 z-50">
          <SymptomSelector
            onSymptomSelect={handleSymptomSelect}
            onClose={() => setShowSymptomSelector(false)}
          />
        </div>
      )}

      {/* Messages - Scrollable content between fixed header and input */}
      <div
        className="flex-1 overflow-y-auto px-4 sm:px-6 py-6 space-y-6 bg-background"
        style={{ marginTop: '64px', marginBottom: '140px' }}
      >
        {messages.map((message) => (
          <div key={message.id}>
            {message.type === "analysis" ? (
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
                              <Badge
                                className={getSeverityColor(
                                  message.analysis.severity,
                                )}
                              >
                                {message.analysis.severity.toUpperCase()} RISK
                              </Badge>
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
                    "max-w-[75%] rounded-2xl px-4 py-3 shadow-sm",
                    message.type === "user"
                      ? "bg-blue-400 text-white"
                      : "bg-muted text-muted-foreground",
                  )}
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
      <div className="fixed bottom-16 left-0 right-0 z-40 border-t border-border/50 bg-background backdrop-blur-lg p-4 shadow-lg">
        <div className="mb-3 flex items-center justify-between gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowSymptomSelector(true)}
            className="flex items-center space-x-2 hover:bg-blue-50 transition-colors duration-200"
          >
            <Stethoscope className="w-4 h-4" />
            <span>Quick Symptom Selector</span>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleNewChat}
            className="h-8 w-8 p-0 text-muted-foreground hover:text-foreground hover:bg-blue-50 transition-colors duration-200"
            title="New Chat"
          >
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex items-end space-x-4">
          <div className="flex-1 relative">
            <Input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={handleKeyPress}
              placeholder="Describe your symptoms (e.g., headache, nausea, fever)..."
              className="min-h-[48px] resize-none rounded-xl border-2 focus:border-blue-400 transition-all duration-300 bg-background shadow-sm"
              disabled={isTyping}
            />
          </div>
          <Button
            onClick={handleSendMessage}
            disabled={!input.trim() || isTyping}
            className="h-[48px] w-[48px] p-0 rounded-xl bg-blue-400 hover:bg-blue-500 shadow-lg hover:shadow-xl transition-all duration-300 group disabled:opacity-50"
          >
            {isTyping ? (
              <Loader2 className="w-4 h-4 animate-spin text-white" />
            ) : (
              <Send className="w-4 h-4 text-white group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform duration-300" />
            )}
          </Button>
        </div>
        <div className="mt-3 flex items-center space-x-2 text-xs text-muted-foreground">
          <AlertTriangle className="w-3 h-3" />
          <span>
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
