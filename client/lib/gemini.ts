const API_KEY = "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"; // OpenRouter API key
const MODEL = "nvidia/nemotron-nano-12b-v2-vl:free"; // OpenRouter model
const API_BASE_URL = "https://openrouter.ai/api/v1";

const MEDICAL_PROMPT = `You are NINA, a professional and empathetic medical AI assistant with emotional intelligence capabilities. Your role is to help users analyze symptoms while being deeply attuned to their emotional state and providing compassionate, supportive care.

EMOTIONAL INTELLIGENCE GUIDELINES:
- Detect emotional distress indicators (anxiety, fear, frustration, sadness) in user messages
- Respond with appropriate empathy and emotional validation
- Use calming language for anxious users
- Adapt your tone based on detected emotional state
- Provide reassurance while maintaining medical professionalism
- Offer anxiety-reducing techniques when appropriate
- Flag severe emotional distress for professional mental health support

MEDICAL GUIDELINES:
- Maintain a professional, caring, and supportive tone at all times
- Engage users with thoughtful follow-up questions to better understand their symptoms
- Offer general health insights, not specific medical diagnoses
- Clearly recommend consulting licensed healthcare professionals for serious or unclear conditions
- Use conversational language, while upholding medical professionalism
- Focus on symptom interpretation, health monitoring, and evidence-based wellness advice

When users describe symptoms:
1. Acknowledge their emotional state first if distress is detected
2. Ask clarifying questions regarding duration, intensity, and related symptoms
3. Provide general explanations of potential causes
4. Suggest appropriate self-care measures, if applicable
5. Include calming techniques for anxious users
6. Emphasize the importance of seeking professional medical evaluation

RESPONSE STRUCTURE:
- Start with emotional validation when needed
- Provide medical information clearly and accessibly
- End with supportive, reassuring language
- Include specific follow-up questions

Keep responses concise yet informative, and always prioritize user well-being, trust, and emotional comfort.`;

// Optional delay utility
async function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Convert file to base64 string
async function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      // Remove the data URL prefix (e.g., "data:image/jpeg;base64,")
      const base64 = result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

interface OpenRouterMessage {
  role: "system" | "user" | "assistant";
  content: string | Array<{
    type: "text" | "image_url";
    text?: string;
    image_url?: {
      url: string;
    };
  }>;
}

interface OpenRouterRequest {
  model: string;
  messages: OpenRouterMessage[];
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
}

interface OpenRouterResponse {
  id: string;
  object: string;
  created: number;
  model: string;
  choices: Array<{
    index: number;
    message?: {
      role: string;
      content: string;
    };
    delta?: {
      content?: string;
    };
    finish_reason: string | null;
  }>;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export async function generateMedicalResponse(
  userMessage: string,
  conversationHistory: string[] = [],
  retries: number = 2,
  documentContext?: string,
  imageFile?: File,
): Promise<string> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      // Build messages array for OpenRouter
      const messages: OpenRouterMessage[] = [
        {
          role: "system",
          content: MEDICAL_PROMPT,
        },
      ];

      // Add conversation history
      conversationHistory.forEach((msg) => {
        messages.push({
          role: "user",
          content: msg,
        });
      });

      // Handle image input if provided
      if (imageFile) {
        // Convert image to base64
        const imageBase64 = await fileToBase64(imageFile);

        messages.push({
          role: "user",
          content: [
            {
              type: "text",
              text: `${userMessage}\n\nPlease analyze this medical image/report and provide insights about what you see. Include any visible medical information, test results, or relevant details.`,
            },
            {
              type: "image_url",
              image_url: {
                url: `data:${imageFile.type};base64,${imageBase64}`,
              },
            },
          ],
        });
      } else {
        // Combine the system prompt with the current user message and document context
        let fullPrompt = `User: ${userMessage}`;

        if (documentContext) {
          fullPrompt += `\n\nDocument Context (from uploaded medical report):\n${documentContext}\n\nPlease analyze this document in the context of the user's query.`;
        }

        fullPrompt += `\n\nNINA:`;

        messages.push({
          role: "user",
          content: fullPrompt,
        });
      }

      // Prepare request for streaming
      const requestBody: OpenRouterRequest = {
        model: MODEL,
        messages,
        stream: true,
        temperature: 0.7,
        max_tokens: 2048,
      };

      const response = await fetch(`${API_BASE_URL}/chat/completions`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${API_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": window.location.origin,
          "X-Title": "NINA Medical Assistant",
        },
        body: JSON.stringify(requestBody),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(`OpenRouter API error: ${response.status} - ${errorData.error?.message || response.statusText}`);
      }

      const reader = response.body?.getReader();
      if (!reader) {
        throw new Error("Failed to get response reader");
      }

      const decoder = new TextDecoder();
      let fullResponse = "";
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || ""; // Keep incomplete line in buffer

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6);
            if (data === "[DONE]") continue;

            try {
              const parsed: OpenRouterResponse = JSON.parse(data);
              const delta = parsed.choices[0]?.delta?.content;
              if (delta) {
                fullResponse += delta;
              }
            } catch (parseError) {
              // Skip invalid JSON chunks
              console.warn("Failed to parse streaming chunk:", parseError);
            }
          }
        }
      }

      return fullResponse;
    } catch (error: any) {
      console.error(`Attempt ${attempt + 1} failed:`, error);

      // Handle image analysis specific errors
      if (imageFile && error?.message?.includes("image")) {
        return "I couldn't analyze the uploaded image. Please ensure the image is clear and contains medical information, then try again.";
      }

      // Retry if service is temporarily unavailable
      if (error?.message?.includes("503") || error?.status === 503) {
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
      if (error?.message?.includes("429") || error?.status === 429) {
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
