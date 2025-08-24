-- Medical Records Table Setup for Supabase
-- Run this SQL in your Supabase SQL Editor to create the required table

-- Create the medical_records table
CREATE TABLE IF NOT EXISTS public.medical_records (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    test_type text NOT NULL,
    test_data jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS medical_records_user_id_idx ON public.medical_records(user_id);
CREATE INDEX IF NOT EXISTS medical_records_test_type_idx ON public.medical_records(test_type);
CREATE INDEX IF NOT EXISTS medical_records_created_at_idx ON public.medical_records(created_at);

-- Enable Row Level Security (RLS)
ALTER TABLE public.medical_records ENABLE ROW LEVEL SECURITY;

-- Create policy to allow users to only access their own records
CREATE POLICY "Users can view their own medical records" ON public.medical_records
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own medical records" ON public.medical_records
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own medical records" ON public.medical_records
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own medical records" ON public.medical_records
    FOR DELETE USING (auth.uid() = user_id);

-- Grant necessary permissions
GRANT ALL ON public.medical_records TO authenticated;
GRANT USAGE ON SCHEMA public TO authenticated;
