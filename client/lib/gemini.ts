import { GoogleGenerativeAI } from "@google/generative-ai";

const API_KEY = "AIzaSyA4LpRxUlFv_h0JyR4tEDQ65iuVNDJiqWM"; // Replace with your Google API key

const genAI = new GoogleGenerativeAI(API_KEY);

const MEDICAL_PROMPT = `You are NINA, a professional and empathetic medical AI assistant. Your role is to help users analyze symptoms, promote health awareness, and offer general wellness guidance.

IMPORTANT GUIDELINES:
- Maintain a professional, caring, and supportive tone at all times.
- Engage users with thoughtful follow-up questions to better understand their symptoms.
- Offer general health insights, not specific medical diagnoses.
- Clearly recommend consulting licensed healthcare professionals for serious or unclear conditions.
- Use conversational language, while upholding medical professionalism.
- Focus on symptom interpretation, health monitoring, and evidence-based wellness advice.

When users describe symptoms:
1. Ask clarifying questions regarding duration, intensity, and related symptoms.
2. Provide general explanations of potential causes.
3. Suggest appropriate self-care measures, if applicable.
4. Emphasize the importance of seeking professional medical evaluation.

Keep responses concise yet informative, and always prioritize user well-being and trust.`;

// Optional delay utility
async function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function generateMedicalResponse(
  userMessage: string,
  conversationHistory: string[] = [],
  retries: number = 2,
): Promise<string> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

      // Start a chat session with prior messages (optional)
      const chat = model.startChat({
        history: conversationHistory.map((msg) => ({
          role: "user",
          parts: [{ text: msg }],
        })),
      });

      // Combine the system prompt with the current user message
      const fullPrompt = `${MEDICAL_PROMPT}\n\nUser: ${userMessage}\n\nNINA:`;

      // Streaming content
      const result = await chat.sendMessageStream(fullPrompt);

      let fullResponse = "";

      for await (const chunk of result.stream) {
        fullResponse += chunk.text(); // Append each streamed token
        // You can also update your UI in real-time here if needed
      }

      return fullResponse;
    } catch (error: any) {
      console.error(`Attempt ${attempt + 1} failed:`, error);

      // Retry if service is temporarily unavailable
      if (error?.message?.includes("[503]") || error?.status === 503) {
        if (attempt < retries) {
          const waitTime = Math.pow(2, attempt) * 1000;
          console.log(`Retrying in ${waitTime}ms...`);
          await delay(waitTime);
          continue;
        } else {
          return "The service is temporarily unavailable. Please try again shortly.";
        }
      }

      // Retry if rate-limited
      if (error?.message?.includes("[429]") || error?.status === 429) {
        if (attempt < retries) {
          await delay(2000);
          continue;
        } else {
          return "Too many requests at the moment. Please try again later.";
        }
      }

      // Generic fallback for other errors
      if (attempt === retries) {
        return "I'm unable to process your request right now. Please try again later.";
      }
    }
  }

  return "Unable to generate a response after multiple attempts.";
}
