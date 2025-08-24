import { createContext, useContext, useEffect, useState } from "react";
import { User, Session } from "@supabase/supabase-js";
import { supabase } from "@shared/supabase";

interface UserProfile {
  firstName?: string;
  lastName?: string;
  email: string;
}

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: any }>;
  signUp: (
    email: string,
    password: string,
    firstName: string,
    lastName: string,
  ) => Promise<{ error: any }>;
  signOut: () => Promise<void>;
  getUserProfile: () => Promise<UserProfile | null>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const getSession = async () => {
      const {
        data: { session },
      } = await supabase.auth.getSession();
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    };

    getSession();

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const signIn = async (email: string, password: string) => {
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    return { error };
  };

  const signUp = async (email: string, password: string, firstName: string, lastName: string) => {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
    });

    if (!error && data.user) {
      try {
        await supabase.from("profiles").insert({
          id: data.user.id,
          email,
          first_name: firstName,
          last_name: lastName,
          full_name: `${firstName} ${lastName}`,
        });
      } catch (profileError) {
        console.warn("Failed to create profile:", profileError);
        // Store in localStorage as fallback
        localStorage.setItem(`profile_${data.user.id}`, JSON.stringify({
          firstName,
          lastName,
          email,
        }));
      }
    }

    return { error };
  };

  const signOut = async () => {
    await supabase.auth.signOut();
  };

  const getUserProfile = async (): Promise<UserProfile | null> => {
    if (!user) return null;

    try {
      const { data, error } = await supabase
        .from("profiles")
        .select("first_name, last_name, email")
        .eq("id", user.id)
        .single();

      if (error || !data) {
        // Fallback to localStorage
        const fallbackProfile = localStorage.getItem(`profile_${user.id}`);
        if (fallbackProfile) {
          const parsed = JSON.parse(fallbackProfile);
          return {
            firstName: parsed.firstName,
            lastName: parsed.lastName,
            email: parsed.email || user.email || "",
          };
        }
        return {
          firstName: "",
          lastName: "",
          email: user.email || "",
        };
      }

      return {
        firstName: data.first_name || "",
        lastName: data.last_name || "",
        email: data.email || user.email || "",
      };
    } catch (error) {
      console.warn("Error fetching user profile:", error);
      return {
        firstName: "",
        lastName: "",
        email: user.email || "",
      };
    }
  };

  const value = {
    user,
    session,
    loading,
    signIn,
    signUp,
    signOut,
    getUserProfile,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
