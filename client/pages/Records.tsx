import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate } from "react-router-dom";
import { supabase } from "@shared/supabase";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import MainLayout from "@/components/MainLayout";
import RecordAnalytics from "@/components/RecordAnalytics";
import {
  Save,
  Calendar,
  Activity,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  Eye,
  Trash2,
  Heart,
  Pill,
  Stethoscope,
  User,
  Plus,
  Edit,
  FileText,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface TestParameter {
  name: string;
  unit: string;
  normalRange: string;
  value?: string;
  status?: "normal" | "high" | "low";
}

interface MedicalTest {
  id: string;
  name: string;
  parameters: TestParameter[];
}

const medicalTests: MedicalTest[] = [
  {
    id: "cbc",
    name: "Complete Blood Count (CBC)",
    parameters: [
      {
        name: "Hemoglobin",
        unit: "g/dL",
        normalRange: "13.5–17.5 (M), 12.0–15.5 (F)",
      },
      { name: "WBC Count", unit: "cells/mcL", normalRange: "4,500–11,000" },
      {
        name: "RBC Count",
        unit: "million/mcL",
        normalRange: "4.7–6.1 (M), 4.2–5.4 (F)",
      },
      { name: "Hematocrit", unit: "%", normalRange: "41–50 (M), 36–44 (F)" },
      { name: "Platelet Count", unit: "/mcL", normalRange: "150,000–450,000" },
      { name: "MCV", unit: "fL", normalRange: "80–100" },
      { name: "MCH", unit: "pg", normalRange: "27–33" },
      { name: "MCHC", unit: "g/dL", normalRange: "32–36" },
      { name: "RDW", unit: "%", normalRange: "11.5–14.5" },
    ],
  },
  {
    id: "lft",
    name: "Liver Function Test (LFT)",
    parameters: [
      { name: "ALT (SGPT)", unit: "U/L", normalRange: "7–56" },
      { name: "AST (SGOT)", unit: "U/L", normalRange: "10–40" },
      { name: "ALP", unit: "IU/L", normalRange: "44–147" },
      { name: "Bilirubin Total", unit: "mg/dL", normalRange: "0.1–1.2" },
      { name: "Bilirubin Direct", unit: "mg/dL", normalRange: "0–0.3" },
      { name: "Albumin", unit: "g/dL", normalRange: "3.4–5.4" },
      { name: "Total Protein", unit: "g/dL", normalRange: "6.0–8.3" },
      { name: "GGT", unit: "U/L", normalRange: "8–61" },
    ],
  },
  {
    id: "kft",
    name: "Kidney Function Test (KFT)",
    parameters: [
      { name: "Creatinine", unit: "mg/dL", normalRange: "0.6–1.3" },
      { name: "Urea", unit: "mg/dL", normalRange: "7–20" },
      { name: "Uric Acid", unit: "mg/dL", normalRange: "3.5–7.2" },
      { name: "BUN", unit: "mg/dL", normalRange: "6–24" },
      { name: "eGFR", unit: "mL/min/1.73 m²", normalRange: "> 90" },
      { name: "Sodium", unit: "mmol/L", normalRange: "135–145" },
      { name: "Potassium", unit: "mmol/L", normalRange: "3.5–5.0" },
    ],
  },
  {
    id: "lipid",
    name: "Lipid Profile",
    parameters: [
      { name: "Total Cholesterol", unit: "mg/dL", normalRange: "< 200" },
      {
        name: "HDL",
        unit: "mg/dL",
        normalRange: "> 40 (M), > 50 (F)",
      },
      { name: "LDL", unit: "mg/dL", normalRange: "< 100" },
      { name: "Triglycerides", unit: "mg/dL", normalRange: "< 150" },
      { name: "VLDL", unit: "mg/dL", normalRange: "5��40" },
      { name: "Cholesterol/HDL Ratio", unit: "", normalRange: "< 5" },
    ],
  },
  {
    id: "tft",
    name: "Thyroid Function Test (TFT)",
    parameters: [
      { name: "TSH", unit: "mIU/L", normalRange: "0.4–4.0" },
      { name: "Free T3", unit: "pg/mL", normalRange: "2.3–4.2" },
      { name: "Free T4", unit: "ng/dL", normalRange: "0.8–1.8" },
      { name: "Total T3", unit: "ng/dL", normalRange: "80–200" },
      { name: "Total T4", unit: "µg/dL", normalRange: "5.0–12.0" },
    ],
  },
  {
    id: "blood-sugar",
    name: "Blood Sugar Test",
    parameters: [
      { name: "Fasting Blood Glucose", unit: "mg/dL", normalRange: "70–99" },
      {
        name: "Postprandial Glucose",
        unit: "mg/dL",
        normalRange: "< 140",
      },
      { name: "Random Blood Sugar", unit: "mg/dL", normalRange: "< 200" },
      { name: "Insulin (Fasting)", unit: "µIU/mL", normalRange: "2–25" },
    ],
  },
  {
    id: "urine",
    name: "Urine Routine Test",
    parameters: [
      { name: "Color", unit: "", normalRange: "Pale Yellow" },
      { name: "pH", unit: "", normalRange: "4.5–8.0" },
      { name: "Specific Gravity", unit: "", normalRange: "1.005–1.030" },
      { name: "Protein", unit: "", normalRange: "Negative" },
      { name: "Glucose", unit: "", normalRange: "Negative" },
      { name: "Ketones", unit: "", normalRange: "Negative" },
      { name: "RBCs", unit: "/HPF", normalRange: "0–2" },
      { name: "WBCs", unit: "/HPF", normalRange: "0–5" },
      { name: "Epithelial Cells", unit: "", normalRange: "Occasional" },
    ],
  },
  {
    id: "vitamin-d",
    name: "Vitamin D Test",
    parameters: [
      { name: "25(OH) Vitamin D", unit: "ng/mL", normalRange: "30–100" },
    ],
  },
  {
    id: "hba1c",
    name: "HbA1c Test",
    parameters: [
      {
        name: "HbA1c",
        unit: "%",
        normalRange:
          "< 5.7% (Normal), 5.7–6.4% (Prediabetic), ≥ 6.5% (Diabetic)",
      },
    ],
  },
  {
    id: "electrolytes",
    name: "Electrolyte Panel",
    parameters: [
      { name: "Sodium (Na⁺)", unit: "mmol/L", normalRange: "135–145" },
      { name: "Potassium (K⁺)", unit: "mmol/L", normalRange: "3.5–5.0" },
      { name: "Chloride (Cl⁻)", unit: "mmol/L", normalRange: "98–106" },
      { name: "Bicarbonate (HCO₃⁻)", unit: "mmol/L", normalRange: "22–29" },
      { name: "Calcium (Total)", unit: "mg/dL", normalRange: "8.6–10.2" },
      { name: "Magnesium", unit: "mg/dL", normalRange: "1.7–2.2" },
      { name: "Phosphate", unit: "mg/dL", normalRange: "2.5–4.5" },
    ],
  },
];

interface MedicalHistory {
  id: string;
  condition_name: string;
  diagnosis_date: string;
  icd_code?: string;
  severity: 'mild' | 'moderate' | 'severe';
  status: 'active' | 'resolved' | 'chronic';
  treating_physician?: string;
  treatment_notes?: string;
  symptoms?: string[];
  complications?: string;
  created_at: string;
}

interface VitalSigns {
  id: string;
  measurement_date: string;
  systolic_bp?: number;
  diastolic_bp?: number;
  heart_rate?: number;
  temperature?: number;
  temperature_unit: string;
  weight?: number;
  weight_unit: string;
  height?: number;
  height_unit: string;
  bmi?: number;
  oxygen_saturation?: number;
  respiratory_rate?: number;
  blood_glucose?: number;
  blood_glucose_unit: string;
  notes?: string;
}

interface HealthProfile {
  id: string;
  date_of_birth?: string;
  gender?: string;
  blood_type?: string;
  allergies?: string[];
  medications?: string[];
  chronic_conditions?: string[];
  emergency_contact_name?: string;
  emergency_contact_phone?: string;
  emergency_contact_relationship?: string;
  medical_insurance_provider?: string;
  medical_insurance_id?: string;
  primary_care_physician?: string;
  primary_care_phone?: string;
  smoking_status?: string;
  alcohol_consumption?: string;
  exercise_frequency?: string;
  dietary_restrictions?: string[];
}

export default function Records() {
  const { user, loading } = useAuth();
  const [activeTest, setActiveTest] = useState<string>("");
  const [testData, setTestData] = useState<Record<string, MedicalTest>>({});
  const [savedRecords, setSavedRecords] = useState<any[]>([]);
  const [testDate, setTestDate] = useState<string>(new Date().toISOString().split("T")[0]);

  // PHR state
  const [medicalHistory, setMedicalHistory] = useState<MedicalHistory[]>([]);
  const [vitalSigns, setVitalSigns] = useState<VitalSigns[]>([]);
  const [healthProfile, setHealthProfile] = useState<HealthProfile | null>(null);
  const [activeTab, setActiveTab] = useState<string>("records");

  // Form states for PHR
  const [showMedicalHistoryForm, setShowMedicalHistoryForm] = useState(false);
  const [showVitalSignsForm, setShowVitalSignsForm] = useState(false);
  const [showHealthProfileForm, setShowHealthProfileForm] = useState(false);
  const [editingMedicalHistory, setEditingMedicalHistory] = useState<MedicalHistory | null>(null);
  const [showPrivacySettings, setShowPrivacySettings] = useState(false);
  const [privacySettings, setPrivacySettings] = useState({
    shareWithDoctors: false,
    shareForResearch: false,
    emergencyAccess: true,
    dataRetention: 'indefinite'
  });
  const [editingVitalSigns, setEditingVitalSigns] = useState<VitalSigns | null>(null);

  useEffect(() => {
    // Initialize test data with empty values
    const initialData: Record<string, MedicalTest> = {};
    medicalTests.forEach((test) => {
      initialData[test.id] = {
        ...test,
        parameters: test.parameters.map((param) => ({ ...param, value: "" })),
      };
    });
    setTestData(initialData);

    // Load saved records from Supabase
    if (user?.id) {
      loadRecordsFromSupabase();
      loadPHRData();
    }
  }, [user?.id]);

  // Load records from Supabase
  const loadRecordsFromSupabase = async () => {
    if (!user?.id) return;

    try {
      const { data, error } = await supabase
        .from('medical_records')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Error loading records:', error);
        return;
      }

      // Transform data to match the expected format
      const transformedRecords = data.map(record => ({
        id: record.id,
        testName: record.test_type,
        testId: record.test_type.toLowerCase().replace(/\s+/g, '-'),
        date: new Date(record.created_at).toISOString().split('T')[0],
        parameters: record.test_data.parameters || []
      }));

      setSavedRecords(transformedRecords);
    } catch (error) {
      console.error('Error loading records from Supabase:', error);
    }
  };

  // Load PHR data
  const loadPHRData = async () => {
    if (!user?.id) return;

    try {
      // Load medical history
      const historyResponse = await fetch('/api/medical-history', {
        headers: {
          'Authorization': `Bearer ${user.id}`
        }
      });
      if (historyResponse.ok) {
        const historyData = await historyResponse.json();
        setMedicalHistory(historyData.data || []);
      }

      // Load vital signs
      const vitalsResponse = await fetch('/api/vital-signs?limit=20', {
        headers: {
          'Authorization': `Bearer ${user.id}`
        }
      });
      if (vitalsResponse.ok) {
        const vitalsData = await vitalsResponse.json();
        setVitalSigns(vitalsData.data || []);
      }

      // Load health profile
      const profileResponse = await fetch('/api/health-profile', {
        headers: {
          'Authorization': `Bearer ${user.id}`
        }
      });
      if (profileResponse.ok) {
        const profileData = await profileResponse.json();
        setHealthProfile(profileData.data);
      }
    } catch (error) {
      console.error('Error loading PHR data:', error);
    }
  };

  // Save records to Supabase whenever savedRecords changes
  useEffect(() => {
    if (user?.id && savedRecords.length > 0) {
      // For now, keep localStorage as backup, but prioritize Supabase
      localStorage.setItem(`medicalRecords_${user.id}`, JSON.stringify(savedRecords));
    }
  }, [savedRecords, user?.id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
          <div className="absolute inset-0 w-16 h-16 border-4 border-transparent border-t-blue-400 rounded-full animate-spin animate-reverse"></div>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const evaluateValue = (
    value: string,
    normalRange: string,
  ): "normal" | "high" | "low" => {
    if (!value || value.trim() === "") return "normal";

    const numValue = parseFloat(value);
    if (isNaN(numValue)) return "normal";

    // Simple range checking (can be enhanced)
    if (normalRange.includes("–")) {
      const ranges = normalRange.match(/(\d+\.?\d*)–(\d+\.?\d*)/);
      if (ranges) {
        const min = parseFloat(ranges[1]);
        const max = parseFloat(ranges[2]);
        if (numValue < min) return "low";
        if (numValue > max) return "high";
        return "normal";
      }
    }

    if (normalRange.includes("<")) {
      const maxMatch = normalRange.match(/<\s*(\d+\.?\d*)/);
      if (maxMatch) {
        const max = parseFloat(maxMatch[1]);
        if (numValue >= max) return "high";
        return "normal";
      }
    }

    if (normalRange.includes(">")) {
      const minMatch = normalRange.match(/>\s*(\d+\.?\d*)/);
      if (minMatch) {
        const min = parseFloat(minMatch[1]);
        if (numValue <= min) return "low";
        return "normal";
      }
    }

    return "normal";
  };

  const updateParameterValue = (
    testId: string,
    paramIndex: number,
    value: string,
  ) => {
    setTestData((prev) => {
      const newData = { ...prev };
      const test = { ...newData[testId] };
      const param = { ...test.parameters[paramIndex] };
      param.value = value;
      param.status = evaluateValue(value, param.normalRange);
      test.parameters[paramIndex] = param;
      newData[testId] = test;
      return newData;
    });
  };

  const saveRecord = async () => {
    if (!activeTest || !user?.id) return;

    const currentTest = testData[activeTest];
    const parameters = currentTest.parameters.filter(
      (p) => p.value && p.value.trim() !== "",
    );

    if (parameters.length === 0) return;

    const recordData = {
      user_id: user.id,
      test_type: currentTest.name,
      test_data: {
        parameters,
        date: testDate
      }
    };

    try {
      const { data, error } = await supabase
        .from('medical_records')
        .insert(recordData)
        .select()
        .single();

      if (error) {
        console.error('Error saving record:', error);
        // Fallback to localStorage
        const record = {
          id: Date.now().toString(),
          testName: currentTest.name,
          testId: activeTest,
          date: testDate,
          parameters,
        };
        setSavedRecords((prev) => [record, ...prev]);
        return;
      }

      // Transform the saved record to match the expected format
      const transformedRecord = {
        id: data.id,
        testName: data.test_type,
        testId: activeTest,
        date: new Date(data.created_at).toISOString().split('T')[0],
        parameters: data.test_data.parameters || []
      };

      setSavedRecords((prev) => [transformedRecord, ...prev]);

      // Clear current test data
      setTestData((prev) => {
        const newData = { ...prev };
        const test = { ...newData[activeTest] };
        test.parameters = test.parameters.map((param) => ({
          ...param,
          value: "",
          status: undefined,
        }));
        newData[activeTest] = test;
        return newData;
      });
    } catch (error) {
      console.error('Error saving record to Supabase:', error);
      // Fallback to localStorage
      const record = {
        id: Date.now().toString(),
        testName: currentTest.name,
        testId: activeTest,
        date: testDate,
        parameters,
      };
      setSavedRecords((prev) => [record, ...prev]);
    }
  };

  const deleteRecord = async (recordId: string) => {
    if (!confirm("Are you sure you want to delete this record?")) return;

    try {
      const { error } = await supabase
        .from('medical_records')
        .delete()
        .eq('id', recordId)
        .eq('user_id', user?.id); // Extra safety check

      if (error) {
        console.error('Error deleting record:', error);
        // Fallback to local state update
        setSavedRecords((prev) => {
          const updatedRecords = prev.filter((record) => record.id !== recordId);
          if (user?.id) {
            if (updatedRecords.length === 0) {
              localStorage.removeItem(`medicalRecords_${user.id}`);
            } else {
              localStorage.setItem(`medicalRecords_${user.id}`, JSON.stringify(updatedRecords));
            }
          }
          return updatedRecords;
        });
        return;
      }

      // Update local state
      setSavedRecords((prev) => {
        const updatedRecords = prev.filter((record) => record.id !== recordId);
        if (user?.id) {
          if (updatedRecords.length === 0) {
            localStorage.removeItem(`medicalRecords_${user.id}`);
          } else {
            localStorage.setItem(`medicalRecords_${user.id}`, JSON.stringify(updatedRecords));
          }
        }
        return updatedRecords;
      });
    } catch (error) {
      console.error('Error deleting record from Supabase:', error);
      // Fallback to local state update
      setSavedRecords((prev) => {
        const updatedRecords = prev.filter((record) => record.id !== recordId);
        if (user?.id) {
          if (updatedRecords.length === 0) {
            localStorage.removeItem(`medicalRecords_${user.id}`);
          } else {
            localStorage.setItem(`medicalRecords_${user.id}`, JSON.stringify(updatedRecords));
          }
        }
        return updatedRecords;
      });
    }
  };

  const getStatusColor = (status?: "normal" | "high" | "low") => {
    switch (status) {
      case "high":
        return "bg-red-100 text-red-800 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800";
      case "low":
        return "bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-400 dark:border-yellow-800";
      case "normal":
        return "bg-green-100 text-green-800 border-green-200 dark:bg-green-900/20 dark:text-green-400 dark:border-green-800";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700";
    }
  };

  const getStatusIcon = (status?: "normal" | "high" | "low") => {
    switch (status) {
      case "high":
        return <AlertCircle className="w-4 h-4" />;
      case "low":
        return <AlertTriangle className="w-4 h-4" />;
      case "normal":
        return <CheckCircle className="w-4 h-4" />;
      default:
        return null;
    }
  };

  const currentTest = activeTest ? testData[activeTest] : null;

  return (
    <MainLayout>
      <div className="min-h-[calc(100vh-4rem)] bg-muted/20 pb-16 sm:pb-20">
        <div className="max-w-7xl mx-auto p-3 sm:p-4 md:p-6">
          <div className="space-y-4 sm:space-y-6 md:space-y-8">
            {/* Analytics Section */}
            {savedRecords.length > 0 && (
              <RecordAnalytics savedRecords={savedRecords} />
            )}

            {/* Main Tabs */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="records" className="flex items-center space-x-2">
                  <FileText className="w-4 h-4" />
                  <span>Medical Records</span>
                </TabsTrigger>
                <TabsTrigger value="health-history" className="flex items-center space-x-2">
                  <Heart className="w-4 h-4" />
                  <span>Health History</span>
                </TabsTrigger>
              </TabsList>

              {/* Medical Records Tab */}
              <TabsContent value="records" className="space-y-6">
                {/* Test Selection */}
                <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Activity className="w-4 h-4 sm:w-5 sm:h-5 text-primary" />
                        <span className="text-sm sm:text-base md:text-lg">Select Medical Test</span>
                      </div>
                      <div className="text-xs sm:text-sm font-normal text-muted-foreground">
                        {savedRecords.length} records stored
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Select value={activeTest} onValueChange={setActiveTest}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Choose a medical test to begin" />
                      </SelectTrigger>
                      <SelectContent>
                        {medicalTests.map((test) => (
                          <SelectItem key={test.id} value={test.id}>
                            {test.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </CardContent>
                </Card>

            {/* Test Input Form - only show when a test is selected */}
            {activeTest &&
              (() => {
                const selectedTest = medicalTests.find(
                  (test) => test.id === activeTest,
                );
                if (!selectedTest) return null;
                return (
                  <div className="grid xl:grid-cols-3 lg:grid-cols-2 gap-4 md:gap-8">
                    {/* Input Form */}
                    <div className="xl:col-span-2 lg:col-span-1">
                      <Card className="shadow-sm">
                        <CardHeader>
                          <CardTitle className="flex flex-col sm:flex-row sm:items-center gap-2">
                            <div className="flex items-center space-x-2">
                              <TrendingUp className="w-4 h-4 sm:w-5 sm:h-5 text-blue-500" />
                              <span className="text-xs sm:text-sm md:text-base">{selectedTest.name}</span>
                            </div>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="mb-6">
                            <Label htmlFor="test-date" className="text-sm font-medium">
                              Test Date
                            </Label>
                            <Input
                              id="test-date"
                              type="date"
                              value={testDate}
                              onChange={(e) => setTestDate(e.target.value)}
                              className="mt-2 transition-all duration-300 focus:ring-2 focus:ring-primary/20"
                            />
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
                            {currentTest?.parameters.map((param, index) => (
                              <div key={index} className="space-y-2 sm:space-y-3">
                                <Label
                                  htmlFor={`param-${index}`}
                                  className="text-xs sm:text-sm font-medium"
                                >
                                  {param.name}
                                  {param.unit && (
                                    <span className="text-muted-foreground ml-1">
                                      ({param.unit})
                                    </span>
                                  )}
                                </Label>
                                <div className="space-y-1 sm:space-y-2">
                                  <Input
                                    id={`param-${index}`}
                                    value={param.value || ""}
                                    onChange={(e) =>
                                      updateParameterValue(
                                        activeTest,
                                        index,
                                        e.target.value,
                                      )
                                    }
                                    placeholder={`Enter ${param.name.toLowerCase()}`}
                                    className="transition-all duration-300 focus:ring-2 focus:ring-primary/20 text-sm sm:text-base"
                                  />
                                  <p className="text-xs text-muted-foreground">
                                    Normal: {param.normalRange}
                                  </p>
                                  {param.value && param.status && (
                                    <Badge
                                      className={cn(
                                        "flex items-center space-x-1 w-fit transition-all duration-300 text-xs",
                                        getStatusColor(param.status),
                                      )}
                                    >
                                      {getStatusIcon(param.status)}
                                      <span className="capitalize">
                                        {param.status}
                                      </span>
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                          <div className="mt-8 flex justify-end">
                            <Button
                              onClick={saveRecord}
                              className="bg-blue-400 hover:bg-blue-500 transition-all duration-300"
                            >
                              <Save className="w-4 h-4 mr-2" />
                              Save Record
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    {/* Summary & Saved Records */}
                    <div className="space-y-6">
                      {/* Current Test Summary */}
                      <Card className="shadow-sm">
                        <CardHeader>
                          <CardTitle className="text-sm sm:text-base md:text-lg flex items-center space-x-2">
                            <Activity className="w-4 h-4 sm:w-5 sm:h-5 text-green-500" />
                            <span>Test Summary</span>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            {currentTest?.parameters
                              .filter((p) => p.value && p.value.trim() !== "")
                              .map((param, index) => (
                                <div
                                  key={index}
                                  className="flex flex-col sm:flex-row sm:justify-between sm:items-center p-2 sm:p-3 bg-muted/50 rounded-lg transition-all duration-300 hover:bg-muted gap-1 sm:gap-2"
                                >
                                  <span className="text-xs sm:text-sm font-medium">
                                    {param.name}
                                  </span>
                                  <div className="flex items-center space-x-1 sm:space-x-2">
                                    <span className="text-xs sm:text-sm font-semibold">
                                      {param.value} {param.unit}
                                    </span>
                                    {param.status && (
                                      <Badge
                                        className={cn(
                                          "text-xs px-1 sm:px-2 py-0.5 sm:py-1",
                                          getStatusColor(param.status),
                                        )}
                                      >
                                        {param.status}
                                      </Badge>
                                    )}
                                  </div>
                                </div>
                              ))}
                            {!currentTest?.parameters.some(
                              (p) => p.value && p.value.trim() !== "",
                            ) && (
                              <p className="text-sm text-muted-foreground text-center py-8">
                                No values entered yet
                              </p>
                            )}
                          </div>
                        </CardContent>
                      </Card>

                      {/* Saved Records */}
                      <Card className="shadow-sm">
                        <CardHeader>
                          <CardTitle className="text-sm sm:text-base md:text-lg flex items-center space-x-2">
                            <Calendar className="w-4 h-4 sm:w-5 sm:h-5 text-purple-500" />
                            <span>Saved Records</span>
                          </CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3 sm:space-y-4 max-h-[400px] sm:max-h-[500px] overflow-y-auto pr-1 sm:pr-2">
                            {savedRecords.map((record) => (
                              <Card
                                key={record.id}
                                className="border-0 shadow-md hover:shadow-xl transition-all duration-300 bg-gradient-to-br from-card to-card/80"
                              >
                                <CardContent className="p-2 sm:p-3 md:p-4">
                                <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start mb-2 sm:mb-3 gap-1 sm:gap-2">
                                  <h4 className="font-medium text-xs sm:text-sm">
                                    {record.testName}
                                  </h4>
                                  <div className="flex items-center space-x-1 sm:space-x-2">
                                    <span className="text-xs text-muted-foreground bg-muted px-1 sm:px-2 py-0.5 sm:py-1 rounded">
                                      {record.date}
                                    </span>
                                    <Button
                                      variant="outline"
                                      size="sm"
                                      onClick={() => deleteRecord(record.id)}
                                      className="h-5 w-5 sm:h-6 sm:w-6 p-0 text-red-500 hover:text-red-700 hover:bg-red-50"
                                    >
                                      <Trash2 className="h-2.5 w-2.5 sm:h-3 sm:w-3" />
                                    </Button>
                                    <Dialog>
                                      <DialogTrigger asChild>
                                        <Button
                                          variant="outline"
                                          size="sm"
                                          className="h-5 w-5 sm:h-6 sm:w-6 p-0"
                                        >
                                          <Eye className="h-2.5 w-2.5 sm:h-3 sm:w-3" />
                                        </Button>
                                      </DialogTrigger>
                                      <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto mx-2 sm:mx-4 md:mx-8 border-0 shadow-2xl bg-card/95 backdrop-blur-lg">
                                        <DialogHeader className="pb-4 sm:pb-6 border-b border-border/50">
                                          <DialogTitle className="text-lg sm:text-xl md:text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                                            {record.testName}
                                          </DialogTitle>
                                          <div className="flex items-center space-x-2 text-muted-foreground">
                                            <Calendar className="w-3 h-3 sm:w-4 sm:h-4" />
                                            <span className="text-xs sm:text-sm">
                                              {record.date}
                                            </span>
                                          </div>
                                        </DialogHeader>
                                        <div className="space-y-4 sm:space-y-6 pt-4 sm:pt-6">
                                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                                            {record.parameters.map(
                                              (param: any, idx: number) => (
                                                <Card
                                                  key={idx}
                                                  className="border-0 shadow-md hover:shadow-lg transition-all duration-300 bg-gradient-to-br from-card to-card/80"
                                                >
                                                  <CardContent className="p-3 sm:p-4 md:p-5">
                                                    <div className="flex justify-between items-start mb-2 sm:mb-3">
                                                      <h5 className="font-semibold text-xs sm:text-sm text-foreground">
                                                        {param.name}
                                                      </h5>
                                                      {param.status && (
                                                        <Badge
                                                          className={cn(
                                                            "text-xs px-1 sm:px-2 py-0.5 sm:py-1 shadow-sm",
                                                            getStatusColor(
                                                              param.status,
                                                            ),
                                                          )}
                                                        >
                                                          {getStatusIcon(
                                                            param.status,
                                                          )}
                                                          <span className="ml-1 capitalize font-medium">
                                                            {param.status}
                                                          </span>
                                                        </Badge>
                                                      )}
                                                    </div>
                                                    <div className="space-y-1 sm:space-y-2">
                                                      <p className="text-lg sm:text-xl md:text-2xl font-bold text-foreground">
                                                        {param.value}
                                                        <span className="text-xs sm:text-sm font-normal text-muted-foreground ml-1">
                                                          {param.unit}
                                                        </span>
                                                      </p>
                                                      <div className="bg-muted/30 rounded-md p-1.5 sm:p-2">
                                                        <p className="text-xs text-muted-foreground font-medium">
                                                          Normal Range:{" "}
                                                          {param.normalRange}
                                                        </p>
                                                      </div>
                                                    </div>
                                                  </CardContent>
                                                </Card>
                                              ),
                                            )}
                                          </div>
                                        </div>
                                      </DialogContent>
                                    </Dialog>
                                  </div>
                                </div>
                                <div className="space-y-1 sm:space-y-2">
                                  {record.parameters
                                    .slice(0, 3)
                                    .map((param: any, idx: number) => (
                                      <div
                                        key={idx}
                                        className="flex flex-col sm:flex-row sm:justify-between text-xs gap-0.5 sm:gap-1"
                                      >
                                        <span className="text-muted-foreground font-medium">
                                          {param.name}:
                                        </span>
                                        <div className="flex items-center space-x-1">
                                          <span className="font-medium">
                                            {param.value} {param.unit}
                                          </span>
                                          {param.status && (
                                            <Badge
                                              className={cn(
                                                "text-xs px-0.5 sm:px-1 py-0",
                                                getStatusColor(param.status),
                                              )}
                                            >
                                              {param.status}
                                            </Badge>
                                          )}
                                        </div>
                                      </div>
                                    ))}
                                  {record.parameters.length > 3 && (
                                    <p className="text-xs text-muted-foreground">
                                      +{record.parameters.length - 3} more
                                      parameters
                                    </p>
                                  )}
                                </div>
                                </CardContent>
                              </Card>
                            ))}
                            {savedRecords.length === 0 && (
                              <p className="text-sm text-muted-foreground text-center py-8">
                                No saved records yet
                              </p>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                );
              })()}
              </TabsContent>

              {/* Health History Tab */}
              <TabsContent value="health-history" className="space-y-6">
                {/* Health Profile Summary */}
                <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <User className="w-4 h-4 sm:w-5 sm:h-5 text-primary" />
                        <span className="text-sm sm:text-base md:text-lg">Health Profile</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Button
                          onClick={() => setShowPrivacySettings(true)}
                          variant="outline"
                          size="sm"
                          className="flex items-center space-x-2"
                        >
                          <Shield className="w-4 h-4" />
                          <span>Privacy</span>
                        </Button>
                        <Button
                          onClick={() => setShowHealthProfileForm(true)}
                          size="sm"
                          className="flex items-center space-x-2"
                        >
                          <Edit className="w-4 h-4" />
                          <span>Edit Profile</span>
                        </Button>
                      </div>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {healthProfile ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div className="space-y-2">
                          <Label className="text-sm font-medium">Basic Information</Label>
                          <div className="text-sm text-muted-foreground space-y-1">
                            <p>Age: {healthProfile.date_of_birth ? new Date().getFullYear() - new Date(healthProfile.date_of_birth).getFullYear() : 'Not set'}</p>
                            <p>Gender: {healthProfile.gender || 'Not set'}</p>
                            <p>Blood Type: {healthProfile.blood_type || 'Not set'}</p>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-sm font-medium">Health Conditions</Label>
                          <div className="text-sm text-muted-foreground space-y-1">
                            <p>Allergies: {healthProfile.allergies?.join(', ') || 'None'}</p>
                            <p>Chronic Conditions: {healthProfile.chronic_conditions?.join(', ') || 'None'}</p>
                            <p>Current Medications: {healthProfile.medications?.join(', ') || 'None'}</p>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label className="text-sm font-medium">Lifestyle</Label>
                          <div className="text-sm text-muted-foreground space-y-1">
                            <p>Smoking: {healthProfile.smoking_status || 'Not set'}</p>
                            <p>Exercise: {healthProfile.exercise_frequency || 'Not set'}</p>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <User className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                        <p className="text-muted-foreground mb-4">No health profile found</p>
                        <Button onClick={() => setShowHealthProfileForm(true)}>
                          <Plus className="w-4 h-4 mr-2" />
                          Create Health Profile
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Medical History */}
                <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Stethoscope className="w-4 h-4 sm:w-5 sm:h-5 text-primary" />
                        <span className="text-sm sm:text-base md:text-lg">Medical History</span>
                      </div>
                      <Button
                        onClick={() => setShowMedicalHistoryForm(true)}
                        size="sm"
                        className="flex items-center space-x-2"
                      >
                        <Plus className="w-4 h-4" />
                        <span>Add Condition</span>
                      </Button>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {medicalHistory.length > 0 ? (
                      <div className="space-y-4">
                        {medicalHistory.map((condition) => (
                          <Card key={condition.id} className="border">
                            <CardContent className="p-4">
                              <div className="flex justify-between items-start mb-3">
                                <div>
                                  <h4 className="font-semibold">{condition.condition_name}</h4>
                                  <p className="text-sm text-muted-foreground">
                                    Diagnosed: {new Date(condition.diagnosis_date).toLocaleDateString()}
                                  </p>
                                </div>
                                <div className="flex items-center space-x-2">
                                  <Badge variant={condition.status === 'active' ? 'destructive' : 'secondary'}>
                                    {condition.status}
                                  </Badge>
                                  <Badge variant="outline">
                                    {condition.severity}
                                  </Badge>
                                </div>
                              </div>
                              {condition.treating_physician && (
                                <p className="text-sm text-muted-foreground mb-2">
                                  Physician: {condition.treating_physician}
                                </p>
                              )}
                              {condition.symptoms && condition.symptoms.length > 0 && (
                                <div className="mb-2">
                                  <Label className="text-xs font-medium">Symptoms:</Label>
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {condition.symptoms.map((symptom, idx) => (
                                      <Badge key={idx} variant="outline" className="text-xs">
                                        {symptom}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              )}
                              {condition.treatment_notes && (
                                <p className="text-sm text-muted-foreground">
                                  <strong>Treatment:</strong> {condition.treatment_notes}
                                </p>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Stethoscope className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                        <p className="text-muted-foreground mb-4">No medical history recorded</p>
                        <Button onClick={() => setShowMedicalHistoryForm(true)}>
                          <Plus className="w-4 h-4 mr-2" />
                          Add First Condition
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Vital Signs */}
                <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Heart className="w-4 h-4 sm:w-5 sm:h-5 text-primary" />
                        <span className="text-sm sm:text-base md:text-lg">Vital Signs</span>
                      </div>
                      <Button
                        onClick={() => setShowVitalSignsForm(true)}
                        size="sm"
                        className="flex items-center space-x-2"
                      >
                        <Plus className="w-4 h-4" />
                        <span>Add Reading</span>
                      </Button>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {vitalSigns.length > 0 ? (
                      <div className="space-y-4">
                        {vitalSigns.slice(0, 5).map((reading) => (
                          <Card key={reading.id} className="border">
                            <CardContent className="p-4">
                              <div className="flex justify-between items-start mb-3">
                                <div>
                                  <h4 className="font-semibold">
                                    {new Date(reading.measurement_date).toLocaleDateString()}
                                  </h4>
                                  <p className="text-sm text-muted-foreground">
                                    {new Date(reading.measurement_date).toLocaleTimeString()}
                                  </p>
                                </div>
                              </div>
                              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                                {reading.systolic_bp && reading.diastolic_bp && (
                                  <div>
                                    <Label className="text-xs font-medium">Blood Pressure</Label>
                                    <p className="font-medium">{reading.systolic_bp}/{reading.diastolic_bp} mmHg</p>
                                  </div>
                                )}
                                {reading.heart_rate && (
                                  <div>
                                    <Label className="text-xs font-medium">Heart Rate</Label>
                                    <p className="font-medium">{reading.heart_rate} bpm</p>
                                  </div>
                                )}
                                {reading.temperature && (
                                  <div>
                                    <Label className="text-xs font-medium">Temperature</Label>
                                    <p className="font-medium">{reading.temperature}°{reading.temperature_unit}</p>
                                  </div>
                                )}
                                {reading.blood_glucose && (
                                  <div>
                                    <Label className="text-xs font-medium">Blood Glucose</Label>
                                    <p className="font-medium">{reading.blood_glucose} {reading.blood_glucose_unit}</p>
                                  </div>
                                )}
                                {reading.weight && (
                                  <div>
                                    <Label className="text-xs font-medium">Weight</Label>
                                    <p className="font-medium">{reading.weight} {reading.weight_unit}</p>
                                  </div>
                                )}
                                {reading.bmi && (
                                  <div>
                                    <Label className="text-xs font-medium">BMI</Label>
                                    <p className="font-medium">{reading.bmi}</p>
                                  </div>
                                )}
                              </div>
                            </CardContent>
                          </Card>
                        ))}
                        {vitalSigns.length > 5 && (
                          <p className="text-center text-sm text-muted-foreground">
                            And {vitalSigns.length - 5} more readings...
                          </p>
                        )}
                      </div>
                    ) : (
                      <div className="text-center py-8">
                        <Heart className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                        <p className="text-muted-foreground mb-4">No vital signs recorded</p>
                        <Button onClick={() => setShowVitalSignsForm(true)}>
                          <Plus className="w-4 h-4 mr-2" />
                          Add First Reading
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>

                {/* Health Timeline */}
                <Card className="shadow-md border-0 bg-card/95 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Calendar className="w-4 h-4 sm:w-5 sm:h-5 text-primary" />
                      <span className="text-sm sm:text-base md:text-lg">Health Timeline</span>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <HealthTimeline
                      medicalHistory={medicalHistory}
                      vitalSigns={vitalSigns}
                      medicalRecords={savedRecords}
                    />
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>

            {/* Medical History Form Dialog */}
            <Dialog open={showMedicalHistoryForm} onOpenChange={setShowMedicalHistoryForm}>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingMedicalHistory ? 'Edit Medical Condition' : 'Add Medical Condition'}
                  </DialogTitle>
                </DialogHeader>
                <MedicalHistoryForm
                  condition={editingMedicalHistory}
                  onSave={async (data) => {
                    try {
                      const method = editingMedicalHistory ? 'PUT' : 'POST';
                      const url = editingMedicalHistory
                        ? `/api/medical-history/${editingMedicalHistory.id}`
                        : '/api/medical-history';

                      const response = await fetch(url, {
                        method,
                        headers: {
                          'Content-Type': 'application/json',
                          'Authorization': `Bearer ${user?.id}`
                        },
                        body: JSON.stringify(data)
                      });

                      if (response.ok) {
                        await loadPHRData();
                        setShowMedicalHistoryForm(false);
                        setEditingMedicalHistory(null);
                      }
                    } catch (error) {
                      console.error('Error saving medical history:', error);
                    }
                  }}
                  onCancel={() => {
                    setShowMedicalHistoryForm(false);
                    setEditingMedicalHistory(null);
                  }}
                />
              </DialogContent>
            </Dialog>

            {/* Vital Signs Form Dialog */}
            <Dialog open={showVitalSignsForm} onOpenChange={setShowVitalSignsForm}>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingVitalSigns ? 'Edit Vital Signs' : 'Add Vital Signs Reading'}
                  </DialogTitle>
                </DialogHeader>
                <VitalSignsForm
                  reading={editingVitalSigns}
                  onSave={async (data) => {
                    try {
                      const method = editingVitalSigns ? 'PUT' : 'POST';
                      const url = editingVitalSigns
                        ? `/api/vital-signs/${editingVitalSigns.id}`
                        : '/api/vital-signs';

                      const response = await fetch(url, {
                        method,
                        headers: {
                          'Content-Type': 'application/json',
                          'Authorization': `Bearer ${user?.id}`
                        },
                        body: JSON.stringify(data)
                      });

                      if (response.ok) {
                        await loadPHRData();
                        setShowVitalSignsForm(false);
                        setEditingVitalSigns(null);
                      }
                    } catch (error) {
                      console.error('Error saving vital signs:', error);
                    }
                  }}
                  onCancel={() => {
                    setShowVitalSignsForm(false);
                    setEditingVitalSigns(null);
                  }}
                />
              </DialogContent>
            </Dialog>

            {/* Health Profile Form Dialog */}
            <Dialog open={showHealthProfileForm} onOpenChange={setShowHealthProfileForm}>
              <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>Edit Health Profile</DialogTitle>
                </DialogHeader>
                <HealthProfileForm
                  profile={healthProfile}
                  onSave={async (data) => {
                    try {
                      const response = await fetch('/api/health-profile', {
                        method: 'POST',
                        headers: {
                          'Content-Type': 'application/json',
                          'Authorization': `Bearer ${user?.id}`
                        },
                        body: JSON.stringify(data)
                      });

                      if (response.ok) {
                        await loadPHRData();
                        setShowHealthProfileForm(false);
                      }
                    } catch (error) {
                      console.error('Error saving health profile:', error);
                    }
                  }}
                  onCancel={() => setShowHealthProfileForm(false)}
                />
              </DialogContent>
            </Dialog>

            {/* Privacy Settings Dialog */}
            <Dialog open={showPrivacySettings} onOpenChange={setShowPrivacySettings}>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle className="flex items-center space-x-2">
                    <Shield className="w-5 h-5" />
                    <span>Privacy & Security Settings</span>
                  </DialogTitle>
                </DialogHeader>
                <div className="space-y-6">
                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Data Sharing Preferences</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <Label className="font-medium">Share with Healthcare Providers</Label>
                          <p className="text-sm text-muted-foreground">Allow doctors to access your complete health history</p>
                        </div>
                        <Switch
                          checked={privacySettings.shareWithDoctors}
                          onCheckedChange={(checked) => setPrivacySettings(prev => ({ ...prev, shareWithDoctors: checked }))}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <Label className="font-medium">Emergency Access</Label>
                          <p className="text-sm text-muted-foreground">Allow emergency services to access critical health information</p>
                        </div>
                        <Switch
                          checked={privacySettings.emergencyAccess}
                          onCheckedChange={(checked) => setPrivacySettings(prev => ({ ...prev, emergencyAccess: checked }))}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <Label className="font-medium">Research Participation</Label>
                          <p className="text-sm text-muted-foreground">Contribute anonymized data to medical research</p>
                        </div>
                        <Switch
                          checked={privacySettings.shareForResearch}
                          onCheckedChange={(checked) => setPrivacySettings(prev => ({ ...prev, shareForResearch: checked }))}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Data Management</h3>
                    <div className="space-y-3">
                      <div>
                        <Label className="font-medium">Data Retention</Label>
                        <Select value={privacySettings.dataRetention} onValueChange={(value) => setPrivacySettings(prev => ({ ...prev, dataRetention: value }))}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1year">1 Year</SelectItem>
                            <SelectItem value="5years">5 Years</SelectItem>
                            <SelectItem value="10years">10 Years</SelectItem>
                            <SelectItem value="indefinite">Indefinite</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h3 className="text-lg font-semibold">Audit Log</h3>
                    <div className="p-4 bg-muted rounded-lg">
                      <p className="text-sm text-muted-foreground mb-3">
                        All access to your health data is logged for security and compliance purposes.
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={async () => {
                          try {
                            const response = await fetch('/api/audit/user', {
                              headers: {
                                'Authorization': `Bearer ${user?.id}`
                              }
                            });
                            if (response.ok) {
                              const data = await response.json();
                              console.log('Audit logs:', data);
                              // In a real app, show this in a dialog or table
                            }
                          } catch (error) {
                            console.error('Error fetching audit logs:', error);
                          }
                        }}
                      >
                        View Access History
                      </Button>
                    </div>
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button variant="outline" onClick={() => setShowPrivacySettings(false)}>
                      Cancel
                    </Button>
                    <Button onClick={() => setShowPrivacySettings(false)}>
                      Save Settings
                    </Button>
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}

// Medical History Form Component
function MedicalHistoryForm({ condition, onSave, onCancel }: {
  condition?: MedicalHistory | null;
  onSave: (data: any) => void;
  onCancel: () => void;
}) {
  const [formData, setFormData] = useState({
    condition_name: condition?.condition_name || '',
    diagnosis_date: condition?.diagnosis_date || new Date().toISOString().split('T')[0],
    icd_code: condition?.icd_code || '',
    severity: condition?.severity || 'mild',
    status: condition?.status || 'active',
    treating_physician: condition?.treating_physician || '',
    treatment_notes: condition?.treatment_notes || '',
    symptoms: condition?.symptoms || [],
    complications: condition?.complications || ''
  });

  const [symptomInput, setSymptomInput] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const addSymptom = () => {
    if (symptomInput.trim() && !formData.symptoms.includes(symptomInput.trim())) {
      setFormData(prev => ({
        ...prev,
        symptoms: [...prev.symptoms, symptomInput.trim()]
      }));
      setSymptomInput('');
    }
  };

  const removeSymptom = (symptom: string) => {
    setFormData(prev => ({
      ...prev,
      symptoms: prev.symptoms.filter(s => s !== symptom)
    }));
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <Label htmlFor="condition_name">Condition Name *</Label>
          <Input
            id="condition_name"
            value={formData.condition_name}
            onChange={(e) => setFormData(prev => ({ ...prev, condition_name: e.target.value }))}
            required
          />
        </div>
        <div>
          <Label htmlFor="diagnosis_date">Diagnosis Date *</Label>
          <Input
            id="diagnosis_date"
            type="date"
            value={formData.diagnosis_date}
            onChange={(e) => setFormData(prev => ({ ...prev, diagnosis_date: e.target.value }))}
            required
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <Label htmlFor="icd_code">ICD Code</Label>
          <Input
            id="icd_code"
            value={formData.icd_code}
            onChange={(e) => setFormData(prev => ({ ...prev, icd_code: e.target.value }))}
            placeholder="e.g., J00"
          />
        </div>
        <div>
          <Label htmlFor="severity">Severity</Label>
          <Select value={formData.severity} onValueChange={(value) => setFormData(prev => ({ ...prev, severity: value as any }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="mild">Mild</SelectItem>
              <SelectItem value="moderate">Moderate</SelectItem>
              <SelectItem value="severe">Severe</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label htmlFor="status">Status</Label>
          <Select value={formData.status} onValueChange={(value) => setFormData(prev => ({ ...prev, status: value as any }))}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
              <SelectItem value="chronic">Chronic</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div>
        <Label htmlFor="treating_physician">Treating Physician</Label>
        <Input
          id="treating_physician"
          value={formData.treating_physician}
          onChange={(e) => setFormData(prev => ({ ...prev, treating_physician: e.target.value }))}
        />
      </div>

      <div>
        <Label htmlFor="treatment_notes">Treatment Notes</Label>
        <Textarea
          id="treatment_notes"
          value={formData.treatment_notes}
          onChange={(e) => setFormData(prev => ({ ...prev, treatment_notes: e.target.value }))}
          rows={3}
        />
      </div>

      <div>
        <Label>Symptoms</Label>
        <div className="flex gap-2 mb-2">
          <Input
            value={symptomInput}
            onChange={(e) => setSymptomInput(e.target.value)}
            placeholder="Add symptom"
            onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addSymptom())}
          />
          <Button type="button" onClick={addSymptom} size="sm">
            <Plus className="w-4 h-4" />
          </Button>
        </div>
        <div className="flex flex-wrap gap-2">
          {formData.symptoms.map((symptom, index) => (
            <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeSymptom(symptom)}>
              {symptom} ×
            </Badge>
          ))}
        </div>
      </div>

      <div>
        <Label htmlFor="complications">Complications</Label>
        <Textarea
          id="complications"
          value={formData.complications}
          onChange={(e) => setFormData(prev => ({ ...prev, complications: e.target.value }))}
          rows={2}
        />
      </div>

      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit">
          {condition ? 'Update' : 'Save'} Condition
        </Button>
      </div>
    </form>
  );
}

// Vital Signs Form Component
function VitalSignsForm({ reading, onSave, onCancel }: {
  reading?: VitalSigns | null;
  onSave: (data: any) => void;
  onCancel: () => void;
}) {
  const [formData, setFormData] = useState({
    measurement_date: reading?.measurement_date || new Date().toISOString(),
    systolic_bp: reading?.systolic_bp || '',
    diastolic_bp: reading?.diastolic_bp || '',
    heart_rate: reading?.heart_rate || '',
    temperature: reading?.temperature || '',
    temperature_unit: reading?.temperature_unit || 'C',
    weight: reading?.weight || '',
    weight_unit: reading?.weight_unit || 'kg',
    height: reading?.height || '',
    height_unit: reading?.height_unit || 'cm',
    oxygen_saturation: reading?.oxygen_saturation || '',
    respiratory_rate: reading?.respiratory_rate || '',
    blood_glucose: reading?.blood_glucose || '',
    blood_glucose_unit: reading?.blood_glucose_unit || 'mg/dL',
    notes: reading?.notes || ''
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const submitData = {
      ...formData,
      systolic_bp: formData.systolic_bp ? parseInt(formData.systolic_bp.toString()) : undefined,
      diastolic_bp: formData.diastolic_bp ? parseInt(formData.diastolic_bp.toString()) : undefined,
      heart_rate: formData.heart_rate ? parseInt(formData.heart_rate.toString()) : undefined,
      temperature: formData.temperature ? parseFloat(formData.temperature.toString()) : undefined,
      weight: formData.weight ? parseFloat(formData.weight.toString()) : undefined,
      height: formData.height ? parseFloat(formData.height.toString()) : undefined,
      oxygen_saturation: formData.oxygen_saturation ? parseInt(formData.oxygen_saturation.toString()) : undefined,
      respiratory_rate: formData.respiratory_rate ? parseInt(formData.respiratory_rate.toString()) : undefined,
      blood_glucose: formData.blood_glucose ? parseFloat(formData.blood_glucose.toString()) : undefined
    };
    onSave(submitData);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <Label htmlFor="measurement_date">Measurement Date & Time</Label>
        <Input
          id="measurement_date"
          type="datetime-local"
          value={formData.measurement_date}
          onChange={(e) => setFormData(prev => ({ ...prev, measurement_date: e.target.value }))}
          required
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <Label>Blood Pressure (mmHg)</Label>
          <div className="flex gap-2">
            <Input
              type="number"
              placeholder="Systolic"
              value={formData.systolic_bp}
              onChange={(e) => setFormData(prev => ({ ...prev, systolic_bp: e.target.value }))}
            />
            <span className="flex items-center">/</span>
            <Input
              type="number"
              placeholder="Diastolic"
              value={formData.diastolic_bp}
              onChange={(e) => setFormData(prev => ({ ...prev, diastolic_bp: e.target.value }))}
            />
          </div>
        </div>
        <div>
          <Label htmlFor="heart_rate">Heart Rate (bpm)</Label>
          <Input
            id="heart_rate"
            type="number"
            value={formData.heart_rate}
            onChange={(e) => setFormData(prev => ({ ...prev, heart_rate: e.target.value }))}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <Label>Temperature</Label>
          <div className="flex gap-2">
            <Input
              type="number"
              step="0.1"
              value={formData.temperature}
              onChange={(e) => setFormData(prev => ({ ...prev, temperature: e.target.value }))}
            />
            <Select value={formData.temperature_unit} onValueChange={(value) => setFormData(prev => ({ ...prev, temperature_unit: value }))}>
              <SelectTrigger className="w-20">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="C">°C</SelectItem>
                <SelectItem value="F">°F</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <Label htmlFor="oxygen_saturation">Oxygen Saturation (%)</Label>
          <Input
            id="oxygen_saturation"
            type="number"
            value={formData.oxygen_saturation}
            onChange={(e) => setFormData(prev => ({ ...prev, oxygen_saturation: e.target.value }))}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <Label>Weight</Label>
          <div className="flex gap-2">
            <Input
              type="number"
              step="0.1"
              value={formData.weight}
              onChange={(e) => setFormData(prev => ({ ...prev, weight: e.target.value }))}
            />
            <Select value={formData.weight_unit} onValueChange={(value) => setFormData(prev => ({ ...prev, weight_unit: value }))}>
              <SelectTrigger className="w-20">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="kg">kg</SelectItem>
                <SelectItem value="lbs">lbs</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <Label>Height</Label>
          <div className="flex gap-2">
            <Input
              type="number"
              step="0.1"
              value={formData.height}
              onChange={(e) => setFormData(prev => ({ ...prev, height: e.target.value }))}
            />
            <Select value={formData.height_unit} onValueChange={(value) => setFormData(prev => ({ ...prev, height_unit: value }))}>
              <SelectTrigger className="w-20">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="cm">cm</SelectItem>
                <SelectItem value="in">in</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <Label htmlFor="respiratory_rate">Respiratory Rate (breaths/min)</Label>
          <Input
            id="respiratory_rate"
            type="number"
            value={formData.respiratory_rate}
            onChange={(e) => setFormData(prev => ({ ...prev, respiratory_rate: e.target.value }))}
          />
        </div>
        <div>
          <Label>Blood Glucose</Label>
          <div className="flex gap-2">
            <Input
              type="number"
              step="0.1"
              value={formData.blood_glucose}
              onChange={(e) => setFormData(prev => ({ ...prev, blood_glucose: e.target.value }))}
            />
            <Select value={formData.blood_glucose_unit} onValueChange={(value) => setFormData(prev => ({ ...prev, blood_glucose_unit: value }))}>
              <SelectTrigger className="w-24">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="mg/dL">mg/dL</SelectItem>
                <SelectItem value="mmol/L">mmol/L</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      <div>
        <Label htmlFor="notes">Notes</Label>
        <Textarea
          id="notes"
          value={formData.notes}
          onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
          rows={2}
        />
      </div>

      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit">
          {reading ? 'Update' : 'Save'} Reading
        </Button>
      </div>
    </form>
  );
}

// Health Timeline Component
function HealthTimeline({ medicalHistory, vitalSigns, medicalRecords }: {
  medicalHistory: MedicalHistory[];
  vitalSigns: VitalSigns[];
  medicalRecords: any[];
}) {
  // Combine all events and sort by date
  const events = [
    ...medicalHistory.map(item => ({
      id: item.id,
      type: 'medical-history' as const,
      title: item.condition_name,
      date: item.diagnosis_date,
      description: `Diagnosed: ${item.condition_name}`,
      severity: item.severity,
      status: item.status,
      icon: Stethoscope
    })),
    ...vitalSigns.map(item => ({
      id: item.id,
      type: 'vital-signs' as const,
      title: 'Vital Signs Reading',
      date: item.measurement_date,
      description: `BP: ${item.systolic_bp || 'N/A'}/${item.diastolic_bp || 'N/A'}, HR: ${item.heart_rate || 'N/A'}`,
      icon: Heart
    })),
    ...medicalRecords.map(item => ({
      id: item.id,
      type: 'medical-record' as const,
      title: item.testName,
      date: item.date,
      description: `${item.parameters?.length || 0} parameters recorded`,
      icon: FileText
    }))
  ].sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  type TimelineEvent = typeof events[0];

  const getEventColor = (type: string, severity?: string, status?: string) => {
    switch (type) {
      case 'medical-history':
        if (severity === 'severe') return 'bg-red-500';
        if (severity === 'moderate') return 'bg-yellow-500';
        return 'bg-blue-500';
      case 'vital-signs':
        return 'bg-green-500';
      case 'medical-record':
        return 'bg-indigo-500';
      default:
        return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-4">
      {events.length > 0 ? (
        <div className="space-y-4">
          {events.slice(0, 10).map((event: TimelineEvent, index) => {
            const IconComponent = event.icon;
            return (
              <div key={event.id} className="flex items-start space-x-4">
                <div className="flex flex-col items-center">
                  <div className={`w-10 h-10 rounded-full flex items-center justify-center text-white ${getEventColor(event.type, (event as any).severity, (event as any).status)}`}>
                    <IconComponent className="w-5 h-5" />
                  </div>
                  {index < events.slice(0, 10).length - 1 && (
                    <div className="w-0.5 h-8 bg-border mt-2"></div>
                  )}
                </div>
                <div className="flex-1 pb-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-semibold text-sm">{event.title}</h4>
                    <span className="text-xs text-muted-foreground">
                      {new Date(event.date).toLocaleDateString()}
                    </span>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{event.description}</p>
                  {((event as any).severity || (event as any).status) && (
                    <div className="flex gap-2 mt-2">
                      {(event as any).severity && (
                        <Badge variant="outline" className="text-xs">
                          {(event as any).severity}
                        </Badge>
                      )}
                      {(event as any).status && (
                        <Badge variant={(event as any).status === 'active' ? 'destructive' : 'secondary'} className="text-xs">
                          {(event as any).status}
                        </Badge>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
          {events.length > 10 && (
            <p className="text-center text-sm text-muted-foreground">
              And {events.length - 10} more events...
            </p>
          )}
        </div>
      ) : (
        <div className="text-center py-8">
          <Calendar className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">No health events recorded yet</p>
          <p className="text-sm text-muted-foreground mt-2">
            Start by adding medical history or vital signs
          </p>
        </div>
      )}
    </div>
  );
}

// Health Profile Form Component
function HealthProfileForm({ profile, onSave, onCancel }: {
  profile?: HealthProfile | null;
  onSave: (data: any) => void;
  onCancel: () => void;
}) {
  const [formData, setFormData] = useState({
    date_of_birth: profile?.date_of_birth || '',
    gender: profile?.gender || '',
    blood_type: profile?.blood_type || '',
    allergies: profile?.allergies || [],
    medications: profile?.medications || [],
    chronic_conditions: profile?.chronic_conditions || [],
    emergency_contact_name: profile?.emergency_contact_name || '',
    emergency_contact_phone: profile?.emergency_contact_phone || '',
    emergency_contact_relationship: profile?.emergency_contact_relationship || '',
    medical_insurance_provider: profile?.medical_insurance_provider || '',
    medical_insurance_id: profile?.medical_insurance_id || '',
    primary_care_physician: profile?.primary_care_physician || '',
    primary_care_phone: profile?.primary_care_phone || '',
    smoking_status: profile?.smoking_status || '',
    alcohol_consumption: profile?.alcohol_consumption || '',
    exercise_frequency: profile?.exercise_frequency || '',
    dietary_restrictions: profile?.dietary_restrictions || []
  });

  const [allergyInput, setAllergyInput] = useState('');
  const [medicationInput, setMedicationInput] = useState('');
  const [conditionInput, setConditionInput] = useState('');
  const [dietaryInput, setDietaryInput] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const addItem = (field: string, input: string, setter: (value: string) => void) => {
    if (input.trim() && !formData[field as keyof typeof formData].includes(input.trim())) {
      setFormData(prev => ({
        ...prev,
        [field]: [...(prev[field as keyof typeof formData] as string[]), input.trim()]
      }));
      setter('');
    }
  };

  const removeItem = (field: string, item: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: (prev[field as keyof typeof formData] as string[]).filter(i => i !== item)
    }));
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Basic Information */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Basic Information</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <Label htmlFor="date_of_birth">Date of Birth</Label>
            <Input
              id="date_of_birth"
              type="date"
              value={formData.date_of_birth}
              onChange={(e) => setFormData(prev => ({ ...prev, date_of_birth: e.target.value }))}
            />
          </div>
          <div>
            <Label htmlFor="gender">Gender</Label>
            <Select value={formData.gender} onValueChange={(value) => setFormData(prev => ({ ...prev, gender: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select gender" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="male">Male</SelectItem>
                <SelectItem value="female">Female</SelectItem>
                <SelectItem value="other">Other</SelectItem>
                <SelectItem value="prefer_not_to_say">Prefer not to say</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="blood_type">Blood Type</Label>
            <Select value={formData.blood_type} onValueChange={(value) => setFormData(prev => ({ ...prev, blood_type: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select blood type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="A+">A+</SelectItem>
                <SelectItem value="A-">A-</SelectItem>
                <SelectItem value="B+">B+</SelectItem>
                <SelectItem value="B-">B-</SelectItem>
                <SelectItem value="AB+">AB+</SelectItem>
                <SelectItem value="AB-">AB-</SelectItem>
                <SelectItem value="O+">O+</SelectItem>
                <SelectItem value="O-">O-</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>

      {/* Health Conditions */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Health Conditions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <Label>Allergies</Label>
            <div className="flex gap-2 mb-2">
              <Input
                value={allergyInput}
                onChange={(e) => setAllergyInput(e.target.value)}
                placeholder="Add allergy"
                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addItem('allergies', allergyInput, setAllergyInput))}
              />
              <Button type="button" onClick={() => addItem('allergies', allergyInput, setAllergyInput)} size="sm">
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {formData.allergies.map((allergy, index) => (
                <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeItem('allergies', allergy)}>
                  {allergy} ×
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <Label>Current Medications</Label>
            <div className="flex gap-2 mb-2">
              <Input
                value={medicationInput}
                onChange={(e) => setMedicationInput(e.target.value)}
                placeholder="Add medication"
                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addItem('medications', medicationInput, setMedicationInput))}
              />
              <Button type="button" onClick={() => addItem('medications', medicationInput, setMedicationInput)} size="sm">
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {formData.medications.map((medication, index) => (
                <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeItem('medications', medication)}>
                  {medication} ×
                </Badge>
              ))}
            </div>
          </div>
          <div>
            <Label>Chronic Conditions</Label>
            <div className="flex gap-2 mb-2">
              <Input
                value={conditionInput}
                onChange={(e) => setConditionInput(e.target.value)}
                placeholder="Add condition"
                onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addItem('chronic_conditions', conditionInput, setConditionInput))}
              />
              <Button type="button" onClick={() => addItem('chronic_conditions', conditionInput, setConditionInput)} size="sm">
                <Plus className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex flex-wrap gap-2">
              {formData.chronic_conditions.map((condition, index) => (
                <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeItem('chronic_conditions', condition)}>
                  {condition} ×
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Emergency Contact */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Emergency Contact</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <Label htmlFor="emergency_contact_name">Name</Label>
            <Input
              id="emergency_contact_name"
              value={formData.emergency_contact_name}
              onChange={(e) => setFormData(prev => ({ ...prev, emergency_contact_name: e.target.value }))}
            />
          </div>
          <div>
            <Label htmlFor="emergency_contact_phone">Phone</Label>
            <Input
              id="emergency_contact_phone"
              value={formData.emergency_contact_phone}
              onChange={(e) => setFormData(prev => ({ ...prev, emergency_contact_phone: e.target.value }))}
            />
          </div>
          <div>
            <Label htmlFor="emergency_contact_relationship">Relationship</Label>
            <Input
              id="emergency_contact_relationship"
              value={formData.emergency_contact_relationship}
              onChange={(e) => setFormData(prev => ({ ...prev, emergency_contact_relationship: e.target.value }))}
            />
          </div>
        </div>
      </div>

      {/* Medical Insurance */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Medical Insurance</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <Label htmlFor="medical_insurance_provider">Provider</Label>
            <Input
              id="medical_insurance_provider"
              value={formData.medical_insurance_provider}
              onChange={(e) => setFormData(prev => ({ ...prev, medical_insurance_provider: e.target.value }))}
            />
          </div>
          <div>
            <Label htmlFor="medical_insurance_id">Insurance ID</Label>
            <Input
              id="medical_insurance_id"
              value={formData.medical_insurance_id}
              onChange={(e) => setFormData(prev => ({ ...prev, medical_insurance_id: e.target.value }))}
            />
          </div>
        </div>
      </div>

      {/* Primary Care */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Primary Care</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <Label htmlFor="primary_care_physician">Physician Name</Label>
            <Input
              id="primary_care_physician"
              value={formData.primary_care_physician}
              onChange={(e) => setFormData(prev => ({ ...prev, primary_care_physician: e.target.value }))}
            />
          </div>
          <div>
            <Label htmlFor="primary_care_phone">Phone</Label>
            <Input
              id="primary_care_phone"
              value={formData.primary_care_phone}
              onChange={(e) => setFormData(prev => ({ ...prev, primary_care_phone: e.target.value }))}
            />
          </div>
        </div>
      </div>

      {/* Lifestyle */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold">Lifestyle</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <Label htmlFor="smoking_status">Smoking Status</Label>
            <Select value={formData.smoking_status} onValueChange={(value) => setFormData(prev => ({ ...prev, smoking_status: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="never">Never</SelectItem>
                <SelectItem value="former">Former</SelectItem>
                <SelectItem value="current">Current</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="alcohol_consumption">Alcohol Consumption</Label>
            <Select value={formData.alcohol_consumption} onValueChange={(value) => setFormData(prev => ({ ...prev, alcohol_consumption: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="occasional">Occasional</SelectItem>
                <SelectItem value="moderate">Moderate</SelectItem>
                <SelectItem value="heavy">Heavy</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label htmlFor="exercise_frequency">Exercise Frequency</Label>
            <Select value={formData.exercise_frequency} onValueChange={(value) => setFormData(prev => ({ ...prev, exercise_frequency: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Select frequency" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="rare">Rare</SelectItem>
                <SelectItem value="weekly">Weekly</SelectItem>
                <SelectItem value="daily">Daily</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div>
          <Label>Dietary Restrictions</Label>
          <div className="flex gap-2 mb-2">
            <Input
              value={dietaryInput}
              onChange={(e) => setDietaryInput(e.target.value)}
              placeholder="Add dietary restriction"
              onKeyPress={(e) => e.key === 'Enter' && (e.preventDefault(), addItem('dietary_restrictions', dietaryInput, setDietaryInput))}
            />
            <Button type="button" onClick={() => addItem('dietary_restrictions', dietaryInput, setDietaryInput)} size="sm">
              <Plus className="w-4 h-4" />
            </Button>
          </div>
          <div className="flex flex-wrap gap-2">
            {formData.dietary_restrictions.map((restriction, index) => (
              <Badge key={index} variant="secondary" className="cursor-pointer" onClick={() => removeItem('dietary_restrictions', restriction)}>
                {restriction} ×
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit">
          Save Profile
        </Button>
      </div>
    </form>
  );
}
