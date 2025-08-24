import { createClient } from "@supabase/supabase-js";

const supabaseUrl = "https://kmbedsxtipgoexlexmns.supabase.co";
const supabaseAnonKey =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImttYmVkc3h0aXBnb2V4bGV4bW5zIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTI2OTAxMjUsImV4cCI6MjA2ODI2NjEyNX0.hbf4bfuXYCcbwQVNONcdZu0HakUBgCNnRsl2Oc2V0T0";

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: {
          id: string;
          email: string;
          full_name: string | null;
          created_at: string;
        };
        Insert: {
          id: string;
          email: string;
          full_name?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          email?: string;
          full_name?: string | null;
          created_at?: string;
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
