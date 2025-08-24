import { Card, CardContent } from "@/components/ui/card";
import { Star, Quote } from "lucide-react";
import { cn } from "@/lib/utils";
import { useRef, useEffect } from "react";

interface HealthcareProfessional {
  name: string;
  role: string;
  hospital: string;
  content: string;
  rating: number;
  image?: string;
  specialization: string;
}

const healthcareProfessionals: HealthcareProfessional[] = [
  {
    name: "Dr. Sarah Williams",
    role: "Chief Cardiologist",
    hospital: "Mayo Clinic",
    specialization: "Cardiovascular Medicine",
    content: "NINA's symptom analysis has been remarkably accurate in my practice. It helps patients prepare better questions and understand their conditions before appointments, making consultations more productive.",
    rating: 5
  },
  {
    name: "Dr. Michael Chen",
    role: "Internal Medicine Physician",
    hospital: "Johns Hopkins Hospital",
    specialization: "Internal Medicine",
    content: "As a practicing physician, I've been impressed with NINA's ability to provide preliminary assessments that align with clinical findings. It's become a valuable tool for patient education.",
    rating: 5
  },
  {
    name: "Dr. Emily Rodriguez",
    role: "Emergency Medicine Director",
    hospital: "Cleveland Clinic",
    specialization: "Emergency Medicine",
    content: "NINA helps patients understand when symptoms require immediate attention versus when they can wait. This has reduced unnecessary ER visits while ensuring urgent cases still receive prompt care.",
    rating: 5
  },
  {
    name: "Dr. James Thompson",
    role: "Family Medicine Specialist",
    hospital: "Stanford Health Care",
    specialization: "Family Medicine",
    content: "The AI's understanding of symptom patterns and its ability to ask relevant follow-up questions mirrors clinical reasoning. It's an excellent first-line tool for health assessment.",
    rating: 5
  },
  {
    name: "Dr. Lisa Park",
    role: "Pediatric Physician",
    hospital: "Boston Children's Hospital",
    specialization: "Pediatrics",
    content: "NINA has been particularly helpful for parents trying to understand their children's symptoms. It provides clear, non-alarming guidance while emphasizing when professional care is needed.",
    rating: 5
  },
  {
    name: "Dr. Robert Davis",
    role: "Infectious Disease Specialist",
    hospital: "Cedars-Sinai Medical Center",
    specialization: "Infectious Diseases",
    content: "During the pandemic, NINA proved invaluable for initial symptom screening. Its diagnostic accuracy and ability to triage patients based on symptom severity was impressive.",
    rating: 5
  },
  {
    name: "Dr. Maria Garcia",
    role: "Neurologist",
    hospital: "Mount Sinai Hospital",
    specialization: "Neurology",
    content: "NINA's analysis of neurological symptoms shows deep understanding of complex conditions. It helps patients articulate their symptoms more clearly during consultations.",
    rating: 5
  },
  {
    name: "Dr. David Kim",
    role: "Orthopedic Surgeon",
    hospital: "Hospital for Special Surgery",
    specialization: "Orthopedic Surgery",
    content: "For musculoskeletal complaints, NINA provides excellent initial assessment. It helps patients understand injury mechanisms and guides them on appropriate timing for specialist referrals.",
    rating: 5
  },
  {
    name: "Dr. Jennifer Wilson",
    role: "Dermatologist",
    hospital: "Memorial Sloan Kettering",
    specialization: "Dermatology",
    content: "NINA's ability to assess skin-related symptoms and provide initial guidance has been remarkable. It helps patients understand when dermatological evaluation is necessary.",
    rating: 5
  },
  {
    name: "Dr. Alex Murphy",
    role: "Psychiatrist",
    hospital: "UCLA Medical Center",
    specialization: "Psychiatry",
    content: "The AI's sensitivity in handling mental health symptoms is commendable. It provides supportive guidance while appropriately directing patients to professional mental health resources.",
    rating: 5
  },
  {
    name: "Dr. Rachel Green",
    role: "Oncologist",
    hospital: "MD Anderson Cancer Center",
    specialization: "Oncology",
    content: "NINA has shown remarkable ability to identify concerning symptoms that warrant immediate oncological evaluation, while also providing reassurance for benign conditions.",
    rating: 5
  },
  {
    name: "Dr. Thomas Brown",
    role: "Gastroenterologist",
    hospital: "University of Michigan Hospital",
    specialization: "Gastroenterology",
    content: "For GI symptoms, NINA demonstrates excellent clinical reasoning. It helps patients understand the significance of various digestive symptoms and guides appropriate care timing.",
    rating: 5
  }
];

function HealthcareProfessionalCard({
  professional,
  className
}: {
  professional: HealthcareProfessional;
  className?: string;
}) {
  return (
    <Card className={cn(
      "transition-all duration-300 ease-out shadow-lg hover:shadow-xl border-0 bg-gradient-to-br from-white to-blue-50/30 dark:from-gray-800 dark:to-blue-900/30 h-[300px] w-[380px] flex-shrink-0",
      className
    )}>
      <CardContent className="p-6 h-full flex flex-col">
        <div className="flex items-center mb-4">
          {[...Array(5)].map((_, i) => (
            <Star
              key={i}
              className={cn(
                "w-4 h-4",
                i < professional.rating ? "text-yellow-400 fill-current" : "text-gray-300"
              )}
            />
          ))}
        </div>
        
        <Quote className="w-8 h-8 text-blue-500/30 mb-3" />
        
        <p className="text-gray-700 dark:text-gray-300 mb-6 leading-relaxed text-sm flex-grow line-clamp-4 overflow-hidden">
          "{professional.content}"
        </p>
        
        <div className="flex items-center space-x-4">
          <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-400 rounded-full flex items-center justify-center shadow-lg">
            <span className="text-white font-bold text-sm">
              {professional.name.split(' ').map(n => n[0]).join('')}
            </span>
          </div>
          <div className="flex-1">
            <p className="font-bold text-gray-900 dark:text-white text-sm">
              {professional.name}
            </p>
            <p className="text-xs text-blue-600 dark:text-blue-400 font-medium">
              {professional.role}
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-400">
              {professional.hospital}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-500 italic">
              {professional.specialization}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function HealthcareProfessionalsReviews() {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const scrollContainer = scrollRef.current;
    if (!scrollContainer) return;

    let animationId: number;
    const scroll = () => {
      scrollContainer.scrollLeft += 0.3;
      if (scrollContainer.scrollLeft >= scrollContainer.scrollWidth / 2) {
        scrollContainer.scrollLeft = 0;
      }
      animationId = requestAnimationFrame(scroll);
    };

    animationId = requestAnimationFrame(scroll);

    const handleMouseEnter = () => {
      cancelAnimationFrame(animationId);
    };

    const handleMouseLeave = () => {
      animationId = requestAnimationFrame(scroll);
    };

    scrollContainer.addEventListener('mouseenter', handleMouseEnter);
    scrollContainer.addEventListener('mouseleave', handleMouseLeave);

    return () => {
      cancelAnimationFrame(animationId);
      scrollContainer.removeEventListener('mouseenter', handleMouseEnter);
      scrollContainer.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, []);

  // Duplicate the professionals array for infinite scroll effect
  const duplicatedProfessionals = [...healthcareProfessionals, ...healthcareProfessionals];

  return (
    <div className="w-full overflow-hidden">
      <div
        ref={scrollRef}
        className="flex space-x-6 overflow-x-auto pb-6 px-8 [&::-webkit-scrollbar]:hidden"
        style={{
          scrollbarWidth: 'none',
          msOverflowStyle: 'none'
        }}
      >
        {duplicatedProfessionals.map((professional, index) => (
          <HealthcareProfessionalCard
            key={`${professional.name}-${index}`}
            professional={professional}
          />
        ))}
      </div>
    </div>
  );
}
