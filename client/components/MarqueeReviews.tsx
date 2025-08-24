import { Card, CardContent } from "@/components/ui/card";
import { Star } from "lucide-react";
import { cn } from "@/lib/utils";

interface Review {
  name: string;
  role: string;
  content: string;
  rating: number;
  avatar?: string;
}

const reviews: Review[] = [
  {
    name: "Sarah Johnson",
    role: "Working Mother",
    content: "NINA helped me understand my recurring headaches. The AI analysis was spot-on and saved me a trip to the doctor for something minor.",
    rating: 5
  },
  {
    name: "Dr. Michael Chen",
    role: "Family Physician",
    content: "I recommend NINA to my patients for preliminary symptom assessment. It's remarkably accurate and helps them prepare for consultations.",
    rating: 5
  },
  {
    name: "Emma Rodriguez",
    role: "College Student",
    content: "As a student with limited healthcare access, NINA has been invaluable. Quick, reliable, and helps me know when to seek immediate care.",
    rating: 5
  },
  {
    name: "James Thompson",
    role: "Senior Citizen",
    content: "The interface is so easy to use. NINA explains things in simple terms and helps me track my various health conditions effectively.",
    rating: 5
  },
  {
    name: "Lisa Park",
    role: "Fitness Enthusiast",
    content: "NINA's insights into my workout-related symptoms have been game-changing. It understands the context of my active lifestyle.",
    rating: 5
  },
  {
    name: "Robert Davis",
    role: "Healthcare Worker",
    content: "Even as a healthcare professional, I find NINA's analysis helpful for quick checks. The AI is impressively knowledgeable.",
    rating: 5
  },
  {
    name: "Maria Garcia",
    role: "New Parent",
    content: "NINA helped me navigate early parenthood health concerns. The reassurance and guidance have been incredibly valuable.",
    rating: 5
  },
  {
    name: "David Kim",
    role: "Software Engineer",
    content: "The accuracy of symptom analysis is remarkable. NINA correctly identified my stress-related symptoms and suggested effective remedies.",
    rating: 5
  },
  {
    name: "Jennifer Wilson",
    role: "Teacher",
    content: "NINA's quick responses during school hours help me decide if I need immediate medical attention or can wait until after work.",
    rating: 5
  },
  {
    name: "Alex Murphy",
    role: "Athlete",
    content: "Perfect for sports-related injury assessment. NINA understands the difference between normal training soreness and concerning symptoms.",
    rating: 5
  },
  {
    name: "Rachel Green",
    role: "Small Business Owner",
    content: "The convenience of having medical guidance at my fingertips is incredible. NINA has become my first line of health consultation.",
    rating: 5
  },
  {
    name: "Thomas Brown",
    role: "Retiree",
    content: "Living in a rural area, NINA provides peace of mind. It helps me understand when symptoms warrant a long drive to the hospital.",
    rating: 5
  }
];

// Split reviews into 3 columns with overlap to prevent gaps
const column1 = reviews.slice(0, 6);
const column2 = reviews.slice(4, 10);
const column3 = reviews.slice(6, 12);

function ReviewCard({ review, className }: { review: Review; className?: string }) {
  return (
    <Card className={cn("mb-4 shadow-lg hover:shadow-xl transition-all duration-300", className)}>
      <CardContent className="p-6">
        <div className="flex items-center mb-3">
          {[...Array(5)].map((_, i) => (
            <Star
              key={i}
              className={cn(
                "w-4 h-4",
                i < review.rating ? "text-yellow-400 fill-current" : "text-gray-300"
              )}
            />
          ))}
        </div>
        <p className="text-gray-700 dark:text-gray-300 mb-4 leading-relaxed">
          "{review.content}"
        </p>
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-full flex items-center justify-center">
            <span className="text-white font-semibold text-sm">
              {review.name.split(' ').map(n => n[0]).join('')}
            </span>
          </div>
          <div>
            <p className="font-semibold text-gray-900 dark:text-white">
              {review.name}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              {review.role}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MarqueeColumn({
  reviews,
  direction = "up",
  className
}: {
  reviews: Review[];
  direction?: "up" | "down";
  className?: string;
}) {
  // Create seamless loop by tripling the reviews
  const loopedReviews = [...reviews, ...reviews, ...reviews];

  return (
    <div className={cn("flex flex-col overflow-hidden", className)}>
      <div
        className={cn(
          "flex flex-col space-y-3",
          direction === "up" ? "animate-marquee-up" : "animate-marquee-down"
        )}
      >
        {loopedReviews.map((review, index) => (
          <ReviewCard
            key={`${review.name}-${index}`}
            review={review}
            className="min-h-[180px] flex-shrink-0"
          />
        ))}
      </div>
    </div>
  );
}

export default function MarqueeReviews() {
  return (
    <div className="relative overflow-hidden h-96">
      {/* Gradient overlays for blur effect */}
      <div className="absolute top-0 left-0 right-0 h-20 bg-gradient-to-b from-white via-white/90 to-transparent dark:from-gray-900 dark:via-gray-900/90 z-10" />
      <div className="absolute bottom-0 left-0 right-0 h-20 bg-gradient-to-t from-white via-white/90 to-transparent dark:from-gray-900 dark:via-gray-900/90 z-10" />

      {/* Review columns */}
      <div className="flex space-x-4 h-full">
        <MarqueeColumn
          reviews={column1}
          direction="up"
          className="w-full md:w-1/3 h-full"
        />
        <MarqueeColumn
          reviews={column2}
          direction="down"
          className="hidden md:block w-1/3 h-full"
        />
        <MarqueeColumn
          reviews={column3}
          direction="up"
          className="hidden md:block w-1/3 h-full"
        />
      </div>
    </div>
  );
}
