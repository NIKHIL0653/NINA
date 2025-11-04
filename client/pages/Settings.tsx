import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { useTheme } from "@/lib/theme-context";
import { Navigate } from "react-router-dom";
import MainLayout from "@/components/MainLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Switch,
} from "@/components/ui/switch";
import {
  User,
  Save,
  Palette,
  LogOut,
  Edit,
  Shield,
  Lock,
  Eye,
  EyeOff,
  Bell,
  Smartphone,
  Globe,
} from "lucide-react";

export default function Settings() {
  const { user, loading, signOut, getUserProfile } = useAuth();
  const { theme, setTheme } = useTheme();

  // User profile state
  const [profile, setProfile] = useState({
    firstName: "",
    lastName: "",
    age: "",
    height: "",
    weight: "",
    gender: "",
  });

  const [savedProfile, setSavedProfile] = useState<typeof profile | null>(null);
  const [isEditing, setIsEditing] = useState(false);

  // Privacy & Security settings
  const [privacySettings, setPrivacySettings] = useState({
    dataSharing: false,
    analytics: true,
    emergencyAccess: true,
    twoFactorAuth: false,
    biometricAuth: false,
  });

  // Feature visibility settings
  const [featureSettings, setFeatureSettings] = useState({
    voiceFeatures: true,
    emotionalIndicators: true,
    advancedAnalytics: false,
    emergencyAlerts: true,
    healthReminders: true,
  });

  // Load saved profile and settings on component mount
  useEffect(() => {
    const loadUserData = async () => {
      if (user) {
        // Get user profile data for names
        const userProfile = await getUserProfile();

        // Load saved settings profile
        const saved = localStorage.getItem(`userProfile_${user.id}`);
        if (saved) {
          const parsedProfile = JSON.parse(saved);
          // Merge with user names from signup
          const updatedProfile = {
            ...parsedProfile,
            firstName: userProfile?.firstName || parsedProfile.firstName || "",
            lastName: userProfile?.lastName || parsedProfile.lastName || ""
          };
          setSavedProfile(updatedProfile);
          setProfile(updatedProfile);
        } else {
          // Initialize with names from signup, other fields blank
          const initialProfile = {
            firstName: userProfile?.firstName || "",
            lastName: userProfile?.lastName || "",
            age: "",
            height: "",
            weight: "",
            gender: "",
          };
          setProfile(initialProfile);
        }

        // Load privacy and feature settings
        const savedPrivacy = localStorage.getItem(`privacySettings_${user.id}`);
        if (savedPrivacy) {
          setPrivacySettings(JSON.parse(savedPrivacy));
        }

        const savedFeatures = localStorage.getItem(`featureSettings_${user.id}`);
        if (savedFeatures) {
          setFeatureSettings(JSON.parse(savedFeatures));
        }
      }
    };

    loadUserData();
  }, [user, getUserProfile]);

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

  const handleProfileUpdate = (field: string, value: string) => {
    setProfile((prev) => ({ ...prev, [field]: value }));
  };

  const handleSaveProfile = () => {
    // Save profile to state (in production, this would save to database)
    setSavedProfile({ ...profile });
    setIsEditing(false);

    // Store in localStorage for persistence with user-specific key
    if (user?.id) {
      localStorage.setItem(`userProfile_${user.id}`, JSON.stringify(profile));
    }
  };

  const handleSavePrivacySettings = () => {
    if (user?.id) {
      localStorage.setItem(`privacySettings_${user.id}`, JSON.stringify(privacySettings));
    }
  };

  const handleSaveFeatureSettings = () => {
    if (user?.id) {
      localStorage.setItem(`featureSettings_${user.id}`, JSON.stringify(featureSettings));
    }
  };

  const handleEditProfile = () => {
    setIsEditing(true);
  };

  return (
    <MainLayout>
      <div className="min-h-[calc(100vh-4rem)] bg-background pb-16 sm:pb-20" role="main" aria-label="Settings">
        <div className="max-w-2xl mx-auto p-4 sm:p-6 space-y-4 sm:space-y-6">
          {/* Header */}
          <div className="mb-6 sm:mb-8">
            <h1 className="text-xl sm:text-2xl font-semibold text-foreground mb-2">
              Settings
            </h1>
            <p className="text-sm sm:text-base text-muted-foreground">
              Manage your profile and preferences
            </p>
          </div>

          {/* Profile Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <User className="w-4 h-4 sm:w-5 sm:h-5" />
                  <span className="text-sm sm:text-base">Profile Information</span>
                </div>
                {savedProfile && !isEditing && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleEditProfile}
                    className="flex items-center space-x-2 text-xs sm:text-sm"
                  >
                    <Edit className="w-3 h-3 sm:w-4 sm:h-4" />
                    <span className="hidden sm:inline">Edit</span>
                  </Button>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {savedProfile && !isEditing ? (
                // Display saved profile as simple list
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">First Name</span>
                    <span className="font-medium">{savedProfile.firstName || "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Last Name</span>
                    <span className="font-medium">{savedProfile.lastName || "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Age</span>
                    <span className="font-medium">{savedProfile.age ? `${savedProfile.age} years` : "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Height</span>
                    <span className="font-medium">{savedProfile.height ? `${savedProfile.height} cm` : "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Weight</span>
                    <span className="font-medium">{savedProfile.weight ? `${savedProfile.weight} kg` : "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Gender</span>
                    <span className="font-medium">{savedProfile.gender ? savedProfile.gender.charAt(0).toUpperCase() + savedProfile.gender.slice(1) : "Not provided"}</span>
                  </div>
                  <Separator />
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">BMI</span>
                    <span className="font-medium">
                      {savedProfile.height && savedProfile.weight
                        ? (() => {
                            const heightM = parseFloat(savedProfile.height) / 100;
                            const weightKg = parseFloat(savedProfile.weight);
                            const bmi = (weightKg / (heightM * heightM)).toFixed(1);
                            let category = "";
                            const bmiNum = parseFloat(bmi);
                            if (bmiNum < 18.5) category = " (Underweight)";
                            else if (bmiNum < 25) category = " (Normal)";
                            else if (bmiNum < 30) category = " (Overweight)";
                            else category = " (Obese)";
                            return `${bmi}${category}`;
                          })()
                        : "Not available"}
                    </span>
                  </div>
                </div>
              ) : (
                // Show edit form
                <>
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="firstName">First Name</Label>
                        <Input
                          id="firstName"
                          value={profile.firstName}
                          onChange={(e) => handleProfileUpdate("firstName", e.target.value)}
                          placeholder="Enter your first name"
                        />
                      </div>

                      <div className="space-y-2">
                        <Label htmlFor="lastName">Last Name</Label>
                        <Input
                          id="lastName"
                          value={profile.lastName}
                          onChange={(e) => handleProfileUpdate("lastName", e.target.value)}
                          placeholder="Enter your last name"
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="age">Age</Label>
                      <Input
                        id="age"
                        type="number"
                        value={profile.age}
                        onChange={(e) => handleProfileUpdate("age", e.target.value)}
                        placeholder="Enter your age"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="height">Height (cm)</Label>
                      <Input
                        id="height"
                        type="number"
                        value={profile.height}
                        onChange={(e) => handleProfileUpdate("height", e.target.value)}
                        placeholder="Enter your height in cm"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="weight">Weight (kg)</Label>
                      <Input
                        id="weight"
                        type="number"
                        value={profile.weight}
                        onChange={(e) => handleProfileUpdate("weight", e.target.value)}
                        placeholder="Enter your weight in kg"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="gender">Gender</Label>
                      <Select value={profile.gender} onValueChange={(value) => handleProfileUpdate("gender", value)}>
                        <SelectTrigger className="w-full">
                          <SelectValue placeholder="Select your gender" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="male">Male</SelectItem>
                          <SelectItem value="female">Female</SelectItem>
                          <SelectItem value="other">Other</SelectItem>
                          <SelectItem value="prefer-not-to-say">Prefer not to say</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="flex justify-end space-x-2 pt-4">
                    {savedProfile && (
                      <Button variant="outline" onClick={() => setIsEditing(false)}>
                        Cancel
                      </Button>
                    )}
                    <Button onClick={handleSaveProfile} className="bg-blue-400 hover:bg-blue-500">
                      <Save className="w-4 h-4 mr-2" />
                      Save Profile
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Privacy & Security Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="w-4 h-4 sm:w-5 sm:h-5" />
                <span className="text-sm sm:text-base">Privacy & Security</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Data Sharing</Label>
                  <p className="text-xs text-muted-foreground">Allow anonymous health data for research</p>
                </div>
                <Switch
                  checked={privacySettings.dataSharing}
                  onCheckedChange={(checked) => {
                    setPrivacySettings(prev => ({ ...prev, dataSharing: checked }));
                    handleSavePrivacySettings();
                  }}
                  aria-label="Enable data sharing for research"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Analytics</Label>
                  <p className="text-xs text-muted-foreground">Help improve NINA with usage analytics</p>
                </div>
                <Switch
                  checked={privacySettings.analytics}
                  onCheckedChange={(checked) => {
                    setPrivacySettings(prev => ({ ...prev, analytics: checked }));
                    handleSavePrivacySettings();
                  }}
                  aria-label="Enable usage analytics"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Emergency Access</Label>
                  <p className="text-xs text-muted-foreground">Allow emergency contacts to access your data</p>
                </div>
                <Switch
                  checked={privacySettings.emergencyAccess}
                  onCheckedChange={(checked) => {
                    setPrivacySettings(prev => ({ ...prev, emergencyAccess: checked }));
                    handleSavePrivacySettings();
                  }}
                  aria-label="Allow emergency contacts to access data"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Two-Factor Authentication</Label>
                  <p className="text-xs text-muted-foreground">Add extra security to your account</p>
                </div>
                <Switch
                  checked={privacySettings.twoFactorAuth}
                  onCheckedChange={(checked) => {
                    setPrivacySettings(prev => ({ ...prev, twoFactorAuth: checked }));
                    handleSavePrivacySettings();
                  }}
                  aria-label="Enable two-factor authentication"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Biometric Authentication</Label>
                  <p className="text-xs text-muted-foreground">Use fingerprint or face ID</p>
                </div>
                <Switch
                  checked={privacySettings.biometricAuth}
                  onCheckedChange={(checked) => {
                    setPrivacySettings(prev => ({ ...prev, biometricAuth: checked }));
                    handleSavePrivacySettings();
                  }}
                  aria-label="Enable biometric authentication"
                />
              </div>
            </CardContent>
          </Card>

          {/* Feature Visibility Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Eye className="w-4 h-4 sm:w-5 sm:h-5" />
                <span className="text-sm sm:text-base">Feature Visibility</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Voice Features</Label>
                  <p className="text-xs text-muted-foreground">Enable voice input and text-to-speech</p>
                </div>
                <Switch
                  checked={featureSettings.voiceFeatures}
                  onCheckedChange={(checked) => {
                    setFeatureSettings(prev => ({ ...prev, voiceFeatures: checked }));
                    handleSaveFeatureSettings();
                  }}
                  aria-label="Enable voice input and text-to-speech"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Emotional Indicators</Label>
                  <p className="text-xs text-muted-foreground">Show emotional state analysis</p>
                </div>
                <Switch
                  checked={featureSettings.emotionalIndicators}
                  onCheckedChange={(checked) => {
                    setFeatureSettings(prev => ({ ...prev, emotionalIndicators: checked }));
                    handleSaveFeatureSettings();
                  }}
                  aria-label="Show emotional state analysis"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Advanced Analytics</Label>
                  <p className="text-xs text-muted-foreground">Detailed health trend analysis</p>
                </div>
                <Switch
                  checked={featureSettings.advancedAnalytics}
                  onCheckedChange={(checked) => {
                    setFeatureSettings(prev => ({ ...prev, advancedAnalytics: checked }));
                    handleSaveFeatureSettings();
                  }}
                  aria-label="Enable detailed health trend analysis"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Emergency Alerts</Label>
                  <p className="text-xs text-muted-foreground">Receive emergency notifications</p>
                </div>
                <Switch
                  checked={featureSettings.emergencyAlerts}
                  onCheckedChange={(checked) => {
                    setFeatureSettings(prev => ({ ...prev, emergencyAlerts: checked }));
                    handleSaveFeatureSettings();
                  }}
                  aria-label="Receive emergency notifications"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <Label className="text-sm font-medium">Health Reminders</Label>
                  <p className="text-xs text-muted-foreground">Medication and appointment reminders</p>
                </div>
                <Switch
                  checked={featureSettings.healthReminders}
                  onCheckedChange={(checked) => {
                    setFeatureSettings(prev => ({ ...prev, healthReminders: checked }));
                    handleSaveFeatureSettings();
                  }}
                  aria-label="Enable medication and appointment reminders"
                />
              </div>
            </CardContent>
          </Card>

          {/* Theme Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Palette className="w-4 h-4 sm:w-5 sm:h-5" />
                <span className="text-sm sm:text-base">Appearance</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="theme">Theme</Label>
                  <Select value={theme} onValueChange={setTheme}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="Select theme" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="light">Light</SelectItem>
                      <SelectItem value="dark">Dark</SelectItem>
                      <SelectItem value="system">System</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-sm text-muted-foreground">
                    Choose your preferred theme or use system setting
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Account Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm sm:text-base">Account</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Email</span>
                  <span className="font-medium">{user.email}</span>
                </div>
                <Separator />
                <div className="text-sm text-muted-foreground">
                  For security reasons, email changes require verification through our support team.
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Sign Out Section */}
          <Card className="border-red-200 dark:border-red-800">
            <CardHeader>
              <CardTitle className="text-red-600 dark:text-red-400 text-sm sm:text-base">Sign Out</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">End your session</p>
                  <p className="text-sm text-muted-foreground">
                    Sign out and return to login
                  </p>
                </div>
                <Button
                  onClick={signOut}
                  variant="destructive"
                  className="flex items-center space-x-2"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Sign out</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  );
}
