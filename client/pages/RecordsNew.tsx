import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate } from "react-router-dom";
import { useDarkMode } from "@/hooks/use-dark-mode";
import { useUserDisplayName } from "@/hooks/use-user-display-name";
import { saveMedicalRecord, loadMedicalRecords, deleteMedicalRecord, testDatabaseConnection, MedicalRecord } from "@/lib/medical-records";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import BottomNav from "@/components/BottomNav";
import RecordAnalytics from "@/components/RecordAnalytics";
import {
  Plus,
  ChevronDown,
  ChevronUp,
  Calendar,
  Activity,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  TrendingUp,
  Eye,
  Trash2,
  FileText,
  Heart,
  Brain,
  Droplets,
  Pill,
  Stethoscope,
  User,
  Settings,
  LogOut,
  Moon,
  Sun,
  Clock,
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

interface SavedRecord {
  id: string;
  testName: string;
  testId: string;
  date: string;
  parameters: TestParameter[];
}

interface RecordSection {
  id: string;
  title: string;
  icon: React.ComponentType<any>;
  color: string;
  description: string;
  records: SavedRecord[];
}

const medicalTests: MedicalTest[] = [
  {
    id: "cbc",
    name: "Complete Blood Count (CBC)",
    parameters: [
      { name: "Hemoglobin", unit: "g/dL", normalRange: "13.5–17.5 (M), 12.0–15.5 (F)" },
      { name: "WBC Count", unit: "cells/mcL", normalRange: "4,500–11,000" },
      { name: "RBC Count", unit: "million/mcL", normalRange: "4.7–6.1 (M), 4.2–5.4 (F)" },
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
      { name: "HDL", unit: "mg/dL", normalRange: "> 40 (M), > 50 (F)" },
      { name: "LDL", unit: "mg/dL", normalRange: "< 100" },
      { name: "Triglycerides", unit: "mg/dL", normalRange: "< 150" },
      { name: "VLDL", unit: "mg/dL", normalRange: "5–40" },
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
      { name: "Postprandial Glucose", unit: "mg/dL", normalRange: "< 140" },
      { name: "Random Blood Sugar", unit: "mg/dL", normalRange: "< 200" },
      { name: "Insulin (Fasting)", unit: "µIU/mL", normalRange: "2–25" },
    ],
  },
];

export default function RecordsNew() {
  const { user, loading, signOut } = useAuth();
  const { isDark, toggle } = useDarkMode();
  const { displayName, initials } = useUserDisplayName();
  const [savedRecords, setSavedRecords] = useState<SavedRecord[]>([]);
  const [testData, setTestData] = useState<Record<string, MedicalTest>>({});
  const [activeTest, setActiveTest] = useState<string>("");
  const [testDate, setTestDate] = useState<string>(new Date().toISOString().split("T")[0]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({});
  const [error, setError] = useState("");

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

    console.log("User object:", user);
    console.log("User ID:", user?.id);

    // Test database connection and load saved records
    if (user?.id) {
      console.log("Starting database operations for user:", user.id);
      // Test database and load records
      testDatabaseConnection().then((testResult) => {

        if (testResult.success) {
          // Database is available, load from there
          loadMedicalRecords(user.id).then((records) => {
            setSavedRecords(records);
            setError("");
          }).catch((loadError) => {
            console.warn("Failed to load from database:", loadError);
            setError("");
          });
        } else {
          // Database not available, use localStorage (this is expected)
          loadMedicalRecords(user.id).then((records) => {
            setSavedRecords(records);
            setError("");
          }).catch((fallbackError) => {
            console.warn("Failed to load from localStorage:", fallbackError);
            setSavedRecords([]);
            setError("");
          });
        }
      }).catch((testError) => {
        console.error("Database test error:", testError);
        setError("Cannot connect to database. Please check your connection.");
      });
    } else {
      console.log("No user ID available");
    }
  }, [user?.id]);



  // Group records by type - moved here to ensure consistent hook order
  const groupRecordsByType = (): RecordSection[] => {
    const sections: RecordSection[] = [
      {
        id: "lab-results",
        title: "Lab Results",
        icon: FileText,
        color: "text-blue-600",
        description: "Blood tests, urine tests, and laboratory analyses",
        records: savedRecords.filter(record =>
          ["cbc", "lft", "kft", "lipid", "tft", "blood-sugar", "vitamin-d", "hba1c", "electrolytes", "urine"].includes(record.testId)
        ),
      },
      {
        id: "timeline",
        title: "Health Timeline",
        icon: Clock,
        color: "text-green-600",
        description: "Chronological view of your health events and records",
        records: savedRecords, // All records for timeline view
      },
    ];

    return sections;
  };

  const recordSections = groupRecordsByType();
  const totalRecords = savedRecords.length;

  // Initialize open sections state
  useEffect(() => {
    const initialOpenState: Record<string, boolean> = {};
    recordSections.forEach(section => {
      if (!(section.id in openSections)) {
        initialOpenState[section.id] = section.records.length > 0;
      }
    });
    if (Object.keys(initialOpenState).length > 0) {
      setOpenSections(prev => ({ ...prev, ...initialOpenState }));
    }
  }, [recordSections.length, savedRecords.length]);

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

  const evaluateValue = (value: string, normalRange: string): "normal" | "high" | "low" => {
    if (!value || value.trim() === "") return "normal";
    const numValue = parseFloat(value);
    if (isNaN(numValue)) return "normal";

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

  const updateParameterValue = (testId: string, paramIndex: number, value: string) => {
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
    const record: MedicalRecord = {
      id: Date.now().toString(),
      testName: currentTest.name,
      testId: activeTest,
      date: testDate,
      parameters: currentTest.parameters.filter((p) => p.value && p.value.trim() !== "").map(p => ({ ...p, value: p.value! })),
    };

    // Save to database
    const result = await saveMedicalRecord(user.id, record);

    if (result.success) {
      // Update local state
      setSavedRecords((prev) => [record, ...prev]);

      // Show appropriate message based on whether fallback was used
      if ((result as any).fallback) {
        // Don't show this as an error since it's working as intended
        setError("");
      } else {
        setError(""); // Clear any previous errors
      }

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

      setShowAddForm(false);
      setActiveTest("");
    } else {
      setError(`Failed to save record: ${result.error || "Unknown error"}`);
    }
  };

  const deleteRecord = async (recordId: string) => {
    if (confirm("Are you sure you want to delete this record?") && user?.id) {
      const result = await deleteMedicalRecord(user.id, recordId);

      if (result.success) {
        setSavedRecords((prev) => prev.filter((record) => record.id !== recordId));
        setError(""); // Clear any previous errors
      } else {
        setError(`Failed to delete record: ${result.error || "Unknown error"}`);
      }
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

  return (
    <div className="min-h-screen bg-background">
      {/* Fixed Records Header */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-blue-400 shadow-sm">
        <div className="flex items-center justify-between h-16 px-6">
          {/* Move heading to the left */}
          <h1 className="text-xl font-semibold text-white">Clinical Records</h1>
          
          {/* Profile Dropdown */}
          <div className="flex-1 flex justify-end">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  className="flex items-center space-x-2 px-3 py-1.5 text-white hover:bg-white/20 rounded-lg transition-all duration-300"
                >
                  <div className="w-6 h-6 bg-white/20 rounded-full flex items-center justify-center">
                    <span className="text-xs text-white font-semibold">{initials}</span>
                  </div>
                  <ChevronDown className="w-3 h-3 opacity-70" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <div className="px-3 py-2 border-b">
                  <p className="text-sm font-medium">{displayName}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                </div>
                <DropdownMenuItem asChild>
                  <a
                    href="/settings"
                    className="flex items-center space-x-2 cursor-pointer"
                  >
                    <Settings className="w-4 h-4" />
                    <span>Settings</span>
                  </a>
                </DropdownMenuItem>
                <DropdownMenuItem
                  onClick={toggle}
                  className="flex items-center space-x-2 cursor-pointer"
                >
                  {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                  <span>{isDark ? 'Light Mode' : 'Dark Mode'}</span>
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onClick={signOut}
                  className="flex items-center space-x-2 cursor-pointer text-destructive focus:text-destructive"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Sign out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-16 pb-20">
        <div className="max-w-4xl mx-auto p-4 sm:p-6">
          <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <p className="text-muted-foreground mt-1">
                  Manage your medical records and health data securely
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant="outline" className="px-3 py-1 bg-blue-50 text-blue-700 border-blue-200">
                  {totalRecords} {totalRecords === 1 ? 'record' : 'records'}
                </Badge>
                <Button
                  onClick={() => setShowAddForm(true)}
                  className="bg-blue-400 hover:bg-blue-500 text-white shadow-lg hover:shadow-xl transition-all duration-200"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Add Record
                </Button>
              </div>
            </div>

            {/* Error Display */}
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {/* Search and Analytics */}
            {savedRecords.length > 0 && (
              <>
                <div className="flex flex-col sm:flex-row gap-4">
                  <div className="flex-1">
                    <Input
                      placeholder="Search records, test names, or parameters..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="w-full"
                    />
                  </div>
                </div>
                <RecordAnalytics savedRecords={savedRecords} />
              </>
            )}

            {/* Records Sections with Tabs */}
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="timeline">Timeline</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4 mt-6">
                {recordSections.filter(section => section.id !== 'timeline').map((section) => {
                  const Icon = section.icon;
                  const isOpen = openSections[section.id] ?? section.records.length > 0;
                  const setIsOpen = (open: boolean) => {
                    setOpenSections(prev => ({ ...prev, [section.id]: open }));
                  };

                  return (
                    <Card key={section.id} className="shadow-sm border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 hover:shadow-md transition-all duration-200">
                      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
                        <CollapsibleTrigger asChild>
                          <CardHeader className="cursor-pointer hover:bg-muted/30 transition-colors duration-200 rounded-t-lg">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-4">
                                <div className={cn("p-3 rounded-xl bg-gradient-to-br",
                                  section.color === "text-blue-600" && "from-blue-100 to-blue-50 dark:from-blue-900/30 dark:to-blue-800/20",
                                  section.color === "text-green-600" && "from-green-100 to-green-50 dark:from-green-900/30 dark:to-green-800/20",
                                  section.color === "text-purple-600" && "from-purple-100 to-purple-50 dark:from-purple-900/30 dark:to-purple-800/20",
                                  section.color === "text-indigo-600" && "from-indigo-100 to-indigo-50 dark:from-indigo-900/30 dark:to-indigo-800/20"
                                )}>
                                  <Icon className={cn("w-5 h-5", section.color)} />
                                </div>
                                <div>
                                  <CardTitle className="text-lg font-semibold">{section.title}</CardTitle>
                                  <p className="text-sm text-muted-foreground">{section.description}</p>
                                </div>
                              </div>
                              <div className="flex items-center space-x-3">
                                <Badge variant="secondary" className={cn("px-3 py-1 font-medium",
                                  section.records.length > 0 ? "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400" : "bg-gray-100 text-gray-600"
                                )}>
                                  {section.records.length}
                                </Badge>
                                {isOpen ? (
                                  <ChevronUp className="w-5 h-5 text-muted-foreground transition-transform duration-200" />
                                ) : (
                                  <ChevronDown className="w-5 h-5 text-muted-foreground transition-transform duration-200" />
                                )}
                              </div>
                            </div>
                          </CardHeader>
                        </CollapsibleTrigger>

                        <CollapsibleContent>
                          <CardContent className="pt-0">
                            {section.records.length > 0 ? (
                              <div className="space-y-3">
                                {section.records.map((record) => (
                                  <div
                                    key={record.id}
                                    className="flex flex-col sm:flex-row sm:items-center sm:justify-between p-4 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 hover:shadow-md transition-all duration-200"
                                  >
                                    <div className="flex-1">
                                      <div className="flex flex-col sm:flex-row sm:items-center sm:space-x-3 mb-3">
                                        <h4 className="font-semibold text-foreground text-sm">{record.testName}</h4>
                                        <div className="flex items-center space-x-2 mt-1 sm:mt-0">
                                          <Badge variant="outline" className="text-xs bg-blue-50 text-blue-700 border-blue-200">
                                            <Calendar className="w-3 h-3 mr-1" />
                                            {new Date(record.date).toLocaleDateString('en-US', {
                                              month: 'short',
                                              day: 'numeric'
                                            })}
                                          </Badge>
                                          <Badge variant="secondary" className="text-xs">
                                            {record.parameters.length}
                                          </Badge>
                                        </div>
                                      </div>
                                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1.5">
                                        {record.parameters.slice(0, 3).map((param, idx) => (
                                          <div key={idx} className="flex items-center justify-between text-xs bg-gray-50 dark:bg-gray-700 rounded p-1.5">
                                            <span className="text-muted-foreground font-medium truncate">{param.name}</span>
                                            <div className="flex items-center space-x-1 ml-2">
                                              <span className="font-semibold text-xs">{param.value}</span>
                                              {param.status && (
                                                <div className={cn("w-2 h-2 rounded-full",
                                                  param.status === 'normal' ? 'bg-green-500' :
                                                  param.status === 'high' ? 'bg-red-500' : 'bg-yellow-500'
                                                )}></div>
                                              )}
                                            </div>
                                          </div>
                                        ))}
                                        {record.parameters.length > 3 && (
                                          <div className="flex items-center justify-center text-xs text-muted-foreground bg-muted/50 rounded p-1.5">
                                            +{record.parameters.length - 3}
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                    <div className="flex flex-col space-y-2 mt-3 sm:mt-0">
                                      <Dialog>
                                        <DialogTrigger asChild>
                                          <Button variant="outline" size="sm" className="h-8 px-2">
                                            <Eye className="w-3 h-3 mr-1" />
                                            <span className="text-xs">View</span>
                                          </Button>
                                        </DialogTrigger>
                                        <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
                                          <DialogHeader>
                                            <DialogTitle className="text-xl font-bold text-blue-600">
                                              {record.testName}
                                            </DialogTitle>
                                            <div className="flex items-center space-x-2 text-muted-foreground">
                                              <Calendar className="w-4 h-4" />
                                              <span>{record.date}</span>
                                            </div>
                                          </DialogHeader>
                                          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 pt-6">
                                            {record.parameters.map((param, idx) => (
                                              <Card key={idx} className="border-0 shadow-md">
                                                <CardContent className="p-4">
                                                  <div className="flex justify-between items-start mb-3">
                                                    <h5 className="font-semibold text-sm">{param.name}</h5>
                                                    {param.status && (
                                                      <Badge className={cn("text-xs px-2 py-1", getStatusColor(param.status))}>
                                                        {getStatusIcon(param.status)}
                                                        <span className="ml-1 capitalize">{param.status}</span>
                                                      </Badge>
                                                    )}
                                                  </div>
                                                  <div className="space-y-2">
                                                    <p className="text-2xl font-bold">
                                                      {param.value}
                                                      <span className="text-sm font-normal text-muted-foreground ml-1">
                                                        {param.unit}
                                                      </span>
                                                    </p>
                                                    <div className="bg-muted/30 rounded-md p-2">
                                                      <p className="text-xs text-muted-foreground">
                                                        Normal: {param.normalRange}
                                                      </p>
                                                    </div>
                                                  </div>
                                                </CardContent>
                                              </Card>
                                            ))}
                                          </div>
                                        </DialogContent>
                                      </Dialog>
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={() => deleteRecord(record.id)}
                                        className="text-red-500 hover:text-red-700 hover:bg-red-50 h-8 w-8 p-0"
                                      >
                                        <Trash2 className="w-3 h-3" />
                                      </Button>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div className="text-center py-8 text-muted-foreground">
                                <Icon className="w-12 h-12 mx-auto mb-3 opacity-50" />
                                <p>No {section.title.toLowerCase()} recorded yet</p>
                              </div>
                            )}
                          </CardContent>
                        </CollapsibleContent>
                      </Collapsible>
                    </Card>
                  );
                })}
              </TabsContent>

              <TabsContent value="timeline" className="space-y-4 mt-6">
                <Card className="shadow-sm border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800">
                  <CardHeader>
                    <CardTitle className="flex items-center space-x-2">
                      <Clock className="w-5 h-5 text-green-600" />
                      <span>Health Timeline</span>
                    </CardTitle>
                    <p className="text-sm text-muted-foreground">Chronological view of your health events and records</p>
                  </CardHeader>
                  <CardContent>
                    {savedRecords.length > 0 ? (
                      <div className="space-y-4">
                        {savedRecords
                          .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
                          .map((record, index) => (
                            <div key={record.id} className="flex items-start space-x-4">
                              <div className="flex flex-col items-center">
                                <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                                {index < savedRecords.length - 1 && (
                                  <div className="w-0.5 h-16 bg-gray-300 dark:bg-gray-600 mt-2"></div>
                                )}
                              </div>
                              <div className="flex-1 pb-8">
                                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                                  <div className="flex items-center justify-between mb-2">
                                    <h4 className="font-semibold text-sm">{record.testName}</h4>
                                    <Badge variant="outline" className="text-xs">
                                      <Calendar className="w-3 h-3 mr-1" />
                                      {new Date(record.date).toLocaleDateString()}
                                    </Badge>
                                  </div>
                                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                    {record.parameters.slice(0, 6).map((param, idx) => (
                                      <div key={idx} className="text-xs">
                                        <span className="text-muted-foreground">{param.name}:</span>
                                        <span className="font-medium ml-1">{param.value} {param.unit}</span>
                                        {param.status && (
                                          <span className={cn("ml-1 px-1 py-0.5 rounded text-xs",
                                            param.status === 'normal' ? 'bg-green-100 text-green-800' :
                                            param.status === 'high' ? 'bg-red-100 text-red-800' :
                                            'bg-yellow-100 text-yellow-800'
                                          )}>
                                            {param.status}
                                          </span>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-muted-foreground">
                        <Clock className="w-12 h-12 mx-auto mb-3 opacity-50" />
                        <p>No health events recorded yet</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

            </Tabs>

            {/* Empty State */}
            {totalRecords === 0 && (
              <Card className="text-center py-16 bg-gradient-to-br from-blue-50/50 to-cyan-50/50 dark:from-blue-900/10 dark:to-cyan-900/10 border-2 border-dashed border-blue-200 dark:border-blue-800">
                <CardContent>
                  <div className="w-20 h-20 mx-auto mb-6 bg-gradient-to-br from-blue-100 to-blue-50 dark:from-blue-900/30 dark:to-blue-800/20 rounded-full flex items-center justify-center">
                    <FileText className="w-10 h-10 text-blue-600" />
                  </div>
                  <h3 className="text-2xl font-bold mb-3 text-foreground">Welcome to Your Health Records</h3>
                  <p className="text-muted-foreground mb-8 max-w-md mx-auto leading-relaxed">
                    Securely store and manage your medical test results, track health trends, and get insights into your wellness journey.
                  </p>
                  <div className="space-y-4">
                    <Button
                      onClick={() => setShowAddForm(true)}
                      className="bg-blue-400 hover:bg-blue-500 text-white shadow-lg hover:shadow-xl transition-all duration-200"
                    >
                      <Plus className="w-4 h-4 mr-2" />
                      Add Your First Record
                    </Button>
                    <div className="flex items-center justify-center space-x-6 text-sm text-muted-foreground">
                      <div className="flex items-center space-x-2">
                        <CheckCircle className="w-4 h-4 text-green-500" />
                        <span>Secure Storage</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <TrendingUp className="w-4 h-4 text-blue-500" />
                        <span>Health Analytics</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Activity className="w-4 h-4 text-purple-500" />
                        <span>Trend Tracking</span>
                      </div>
                    </div>

                    {/* Note about local storage */}
                    <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                      <p className="text-sm text-yellow-800 dark:text-yellow-200">
                        <strong>Note:</strong> Your records are currently saved locally in your browser.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* Add Record Dialog */}
        <Dialog open={showAddForm} onOpenChange={setShowAddForm}>
          <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold text-blue-600">
                Add New Medical Record
              </DialogTitle>
            </DialogHeader>
            
            <div className="space-y-6 pt-6">
              {/* Test Selection */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Select Test Type</Label>
                <Select value={activeTest} onValueChange={setActiveTest}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Choose a medical test" />
                  </SelectTrigger>
                  <SelectContent>
                    {medicalTests.map((test) => (
                      <SelectItem key={test.id} value={test.id}>
                        {test.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Date Selection */}
              <div className="space-y-3">
                <Label className="text-base font-medium">Test Date</Label>
                <Input
                  type="date"
                  value={testDate}
                  onChange={(e) => setTestDate(e.target.value)}
                  className="w-full"
                />
              </div>

              {/* Parameters Input */}
              {activeTest && testData[activeTest] && (
                <div className="space-y-4">
                  <Label className="text-base font-medium">Test Parameters</Label>
                  <div className="grid md:grid-cols-2 gap-4">
                    {testData[activeTest].parameters.map((param, index) => (
                      <div key={index} className="space-y-2">
                        <Label className="text-sm font-medium">
                          {param.name}
                          {param.unit && (
                            <span className="text-muted-foreground ml-1">({param.unit})</span>
                          )}
                        </Label>
                        <Input
                          value={param.value || ""}
                          onChange={(e) => updateParameterValue(activeTest, index, e.target.value)}
                          placeholder={`Enter ${param.name.toLowerCase()}`}
                          className="w-full"
                        />
                        <p className="text-xs text-muted-foreground">
                          Normal: {param.normalRange}
                        </p>
                        {param.value && param.status && (
                          <Badge className={cn("flex items-center space-x-1 w-fit", getStatusColor(param.status))}>
                            {getStatusIcon(param.status)}
                            <span className="capitalize">{param.status}</span>
                          </Badge>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Save Button */}
              <div className="flex justify-end space-x-3 pt-6 border-t">
                <Button variant="outline" onClick={() => setShowAddForm(false)}>
                  Cancel
                </Button>
                <Button 
                  onClick={saveRecord} 
                  disabled={!activeTest}
                  className="bg-blue-400 hover:bg-blue-500"
                >
                  Save Record
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Bottom Navigation */}
      <BottomNav />
    </div>
  );
}
