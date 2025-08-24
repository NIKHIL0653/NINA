import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { X } from "lucide-react";

interface SymptomSelectorProps {
  onSymptomSelect: (symptoms: string[]) => void;
  onClose: () => void;
}

const commonSymptoms = [
  "Headache",
  "Fever",
  "Cough",
  "Fatigue",
  "Nausea",
  "Dizziness",
  "Chest pain",
  "Shortness of breath",
  "Abdominal pain",
  "Back pain",
  "Joint pain",
  "Muscle aches",
  "Sore throat",
  "Runny nose",
  "Loss of appetite",
  "Sleep problems",
  "Skin rash",
  "Vomiting",
  "Diarrhea",
  "Constipation",
  "Anxiety",
  "Depression",
  "Memory problems",
  "Difficulty concentrating",
];

const SymptomSelector = ({
  onSymptomSelect,
  onClose,
}: SymptomSelectorProps) => {
  const [selectedSymptoms, setSelectedSymptoms] = useState<string[]>([]);

  const toggleSymptom = (symptom: string) => {
    setSelectedSymptoms((prev) =>
      prev.includes(symptom)
        ? prev.filter((s) => s !== symptom)
        : [...prev, symptom],
    );
  };

  const handleSubmit = () => {
    if (selectedSymptoms.length > 0) {
      onSymptomSelect(selectedSymptoms);
      onClose();
    }
  };

  return (
    <Card className="w-full max-w-2xl mx-auto shadow-lg">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>Select Your Symptoms</CardTitle>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="w-4 h-4" />
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">
          Choose the symptoms you're experiencing to help NINA provide better
          assistance
        </p>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Selected symptoms */}
          {selectedSymptoms.length > 0 && (
            <div className="space-y-2">
              <p className="text-sm font-medium">Selected symptoms:</p>
              <div className="flex flex-wrap gap-2">
                {selectedSymptoms.map((symptom) => (
                  <Badge
                    key={symptom}
                    variant="default"
                    className="cursor-pointer"
                    onClick={() => toggleSymptom(symptom)}
                  >
                    {symptom}
                    <X className="w-3 h-3 ml-1" />
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Available symptoms */}
          <div className="space-y-2">
            <p className="text-sm font-medium">Common symptoms:</p>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 max-h-64 overflow-y-auto">
              {commonSymptoms.map((symptom) => (
                <Button
                  key={symptom}
                  variant={
                    selectedSymptoms.includes(symptom) ? "default" : "outline"
                  }
                  size="sm"
                  className="justify-start text-left h-auto py-2 px-3 text-xs min-h-[36px] whitespace-normal"
                  onClick={() => toggleSymptom(symptom)}
                >
                  {symptom}
                </Button>
              ))}
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex space-x-2 pt-4">
            <Button
              onClick={handleSubmit}
              disabled={selectedSymptoms.length === 0}
              className="flex-1"
            >
              Submit Symptoms ({selectedSymptoms.length})
            </Button>
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default SymptomSelector;
