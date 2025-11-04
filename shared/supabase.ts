import { createClient } from "@supabase/supabase-js";

const supabaseUrl = "https://fdzoxcmtadcqcfoikplk.supabase.co";
const supabaseAnonKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZkem94Y210YWRjcWNmb2lrcGxrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTkxMzU5MjcsImV4cCI6MjA3NDcxMTkyN30.zCEBlE_pMahRkZ0SbHtgq8BZEre4a4qzGL0NjqwKMFc";

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          email: string;
          full_name: string | null;
          role: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id: string;
          email: string;
          full_name?: string | null;
          role?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          email?: string;
          full_name?: string | null;
          role?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      medical_records: {
        Row: {
          id: string;
          user_id: string;
          test_type: string;
          test_data: any;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          test_type: string;
          test_data: any;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          test_type?: string;
          test_data?: any;
          created_at?: string;
        };
      };
      appointments: {
        Row: {
          id: string;
          user_id: string;
          provider_name: string;
          provider_specialty: string | null;
          appointment_date: string;
          appointment_type: string;
          location: string | null;
          notes: string | null;
          status: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          provider_name: string;
          provider_specialty?: string | null;
          appointment_date: string;
          appointment_type: string;
          location?: string | null;
          notes?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          provider_name?: string;
          provider_specialty?: string | null;
          appointment_date?: string;
          appointment_type?: string;
          location?: string | null;
          notes?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      prescriptions: {
        Row: {
          id: string;
          user_id: string;
          medication_name: string;
          dosage: string;
          frequency: string;
          prescribing_doctor: string;
          start_date: string;
          end_date: string | null;
          instructions: string | null;
          side_effects: string | null;
          status: string;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          medication_name: string;
          dosage: string;
          frequency: string;
          prescribing_doctor: string;
          start_date: string;
          end_date?: string | null;
          instructions?: string | null;
          side_effects?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          medication_name?: string;
          dosage?: string;
          frequency?: string;
          prescribing_doctor?: string;
          start_date?: string;
          end_date?: string | null;
          instructions?: string | null;
          side_effects?: string | null;
          status?: string;
          created_at?: string;
          updated_at?: string;
        };
      };
      emergency_contacts: {
        Row: {
          id: string;
          user_id: string;
          name: string;
          relationship: string;
          phone: string;
          email: string | null;
          address: string | null;
          is_primary: boolean;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          name: string;
          relationship: string;
          phone: string;
          email?: string | null;
          address?: string | null;
          is_primary?: boolean;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          name?: string;
          relationship?: string;
          phone?: string;
          email?: string | null;
          address?: string | null;
          is_primary?: boolean;
          created_at?: string;
          updated_at?: string;
        };
      };
      chat_history: {
        Row: {
          id: string;
          user_id: string;
          messages: any;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          messages: any;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          messages?: any;
          created_at?: string;
        };
      };
    };
  };
}
