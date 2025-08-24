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
  User,
  Save,
  Palette,
  LogOut,
  Edit,
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
  });

  const [savedProfile, setSavedProfile] = useState<typeof profile | null>(null);
  const [isEditing, setIsEditing] = useState(false);

  // Load saved profile on component mount
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
          };
          setProfile(initialProfile);
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

  const handleEditProfile = () => {
    setIsEditing(true);
  };

  return (
    <MainLayout>
      <div className="min-h-[calc(100vh-4rem)] bg-background pb-20">
        <div className="max-w-2xl mx-auto p-6 space-y-6">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-2xl font-semibold text-foreground mb-2">
              Settings
            </h1>
            <p className="text-muted-foreground">
              Manage your profile and preferences
            </p>
          </div>

          {/* Profile Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <User className="w-5 h-5" />
                  <span>Profile Information</span>
                </div>
                {savedProfile && !isEditing && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleEditProfile}
                    className="flex items-center space-x-2"
                  >
                    <Edit className="w-4 h-4" />
                    <span>Edit</span>
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
                </div>
              ) : (
                // Show edit form
                <>
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
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

          {/* Theme Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Palette className="w-5 h-5" />
                <span>Appearance</span>
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
              <CardTitle>Account</CardTitle>
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
              <CardTitle className="text-red-600 dark:text-red-400">Sign Out</CardTitle>
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
