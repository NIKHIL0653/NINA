import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import { Navigate } from "react-router-dom";
import MainLayout from "@/components/MainLayout";
import BottomNav from "@/components/BottomNav";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { User, Mail, Phone, MapPin, Calendar, Edit, Save, X, Plus } from "lucide-react";
import { cn } from "@/lib/utils";
import { supabase } from "@shared/supabase";
import { useUserDisplayName } from "@/hooks/use-user-display-name";


export default function Profile() {
  const { user, loading } = useAuth();
  const { displayName, initials } = useUserDisplayName();






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

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Fixed Header */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-blue-400 shadow-sm">
        <div className="h-16 flex items-center justify-center">
          <h1 className="text-xl font-semibold text-white">Profile</h1>
        </div>
      </nav>

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4 sm:py-6 bg-background" style={{ marginTop: '64px', marginBottom: '120px' }}>
        {/* User Profile Card */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center space-x-4">
              <div className="w-16 h-16 bg-blue-400 rounded-full flex items-center justify-center">
                <span className="text-2xl text-white font-semibold">{initials}</span>
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-foreground">{displayName}</h2>
                <p className="text-muted-foreground">{user.email}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Member since {new Date(user.created_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long'
                  })}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

      </div>

      {/* Bottom Navigation */}
      <BottomNav />
    </div>
  );
}