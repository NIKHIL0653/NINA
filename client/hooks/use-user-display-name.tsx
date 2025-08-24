import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";

export function useUserDisplayName() {
  const { user, getUserProfile } = useAuth();
  const [displayName, setDisplayName] = useState("");
  const [initials, setInitials] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadDisplayName = async () => {
      if (!user) {
        setDisplayName("");
        setInitials("");
        setLoading(false);
        return;
      }

      try {
        console.log("Loading user profile for:", user.id);
        const userProfile = await getUserProfile();
        console.log("User profile result:", userProfile);

        if (userProfile?.firstName) {
          setDisplayName(userProfile.firstName);
          // Generate initials
          const firstInitial = userProfile.firstName.charAt(0).toUpperCase();
          const lastInitial = userProfile.lastName ? userProfile.lastName.charAt(0).toUpperCase() : "";
          setInitials(firstInitial + lastInitial);
          console.log("Using profile name:", userProfile.firstName, "Initials:", firstInitial + lastInitial);
        } else {
          // Fallback to email prefix if no first name
          const emailName = user.email?.split("@")[0] || "User";
          setDisplayName(emailName);
          setInitials(emailName.charAt(0).toUpperCase());
          console.log("Using fallback email name:", emailName);
        }
      } catch (error) {
        console.warn("Error loading user display name:", error);
        const emailName = user.email?.split("@")[0] || "User";
        setDisplayName(emailName);
        setInitials(emailName.charAt(0).toUpperCase());
      } finally {
        setLoading(false);
      }
    };

    loadDisplayName();
  }, [user, getUserProfile]);

  return { displayName, initials, loading };
}
