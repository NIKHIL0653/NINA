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

-- Create appointments table
CREATE TABLE IF NOT EXISTS public.appointments (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    provider_name text NOT NULL,
    provider_specialty text,
    appointment_date timestamp with time zone NOT NULL,
    appointment_type text NOT NULL,
    location text,
    notes text,
    status text DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'completed', 'cancelled', 'no_show')),
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for appointments
CREATE INDEX IF NOT EXISTS appointments_user_id_idx ON public.appointments(user_id);
CREATE INDEX IF NOT EXISTS appointments_date_idx ON public.appointments(appointment_date);
CREATE INDEX IF NOT EXISTS appointments_status_idx ON public.appointments(status);

-- Enable RLS for appointments
ALTER TABLE public.appointments ENABLE ROW LEVEL SECURITY;

-- Create policies for appointments
CREATE POLICY "Users can view their own appointments" ON public.appointments
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own appointments" ON public.appointments
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own appointments" ON public.appointments
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own appointments" ON public.appointments
    FOR DELETE USING (auth.uid() = user_id);

-- Create prescriptions table
CREATE TABLE IF NOT EXISTS public.prescriptions (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    medication_name text NOT NULL,
    dosage text NOT NULL,
    frequency text NOT NULL,
    prescribing_doctor text NOT NULL,
    start_date date NOT NULL,
    end_date date,
    instructions text,
    side_effects text,
    status text DEFAULT 'active' CHECK (status IN ('active', 'completed', 'discontinued')),
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for prescriptions
CREATE INDEX IF NOT EXISTS prescriptions_user_id_idx ON public.prescriptions(user_id);
CREATE INDEX IF NOT EXISTS prescriptions_status_idx ON public.prescriptions(status);
CREATE INDEX IF NOT EXISTS prescriptions_start_date_idx ON public.prescriptions(start_date);

-- Enable RLS for prescriptions
ALTER TABLE public.prescriptions ENABLE ROW LEVEL SECURITY;

-- Create policies for prescriptions
CREATE POLICY "Users can view their own prescriptions" ON public.prescriptions
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own prescriptions" ON public.prescriptions
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own prescriptions" ON public.prescriptions
    FOR UPDATE USING (auth.uid() = user_id);


-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = timezone('utc'::text, now());
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON public.appointments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_prescriptions_updated_at BEFORE UPDATE ON public.prescriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- Create medical_history table for PHR
CREATE TABLE IF NOT EXISTS public.medical_history (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    condition_name text NOT NULL,
    diagnosis_date date NOT NULL,
    icd_code text,
    severity text CHECK (severity IN ('mild', 'moderate', 'severe')),
    status text DEFAULT 'active' CHECK (status IN ('active', 'resolved', 'chronic')),
    treating_physician text,
    treatment_notes text,
    symptoms text[],
    complications text,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for medical_history
CREATE INDEX IF NOT EXISTS medical_history_user_id_idx ON public.medical_history(user_id);
CREATE INDEX IF NOT EXISTS medical_history_condition_name_idx ON public.medical_history(condition_name);
CREATE INDEX IF NOT EXISTS medical_history_status_idx ON public.medical_history(status);
CREATE INDEX IF NOT EXISTS medical_history_diagnosis_date_idx ON public.medical_history(diagnosis_date);

-- Enable RLS for medical_history
ALTER TABLE public.medical_history ENABLE ROW LEVEL SECURITY;

-- Create policies for medical_history
CREATE POLICY "Users can view their own medical history" ON public.medical_history
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own medical history" ON public.medical_history
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own medical history" ON public.medical_history
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own medical history" ON public.medical_history
    FOR DELETE USING (auth.uid() = user_id);

-- Create vital_signs table for PHR
CREATE TABLE IF NOT EXISTS public.vital_signs (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    measurement_date timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    systolic_bp integer,
    diastolic_bp integer,
    heart_rate integer,
    temperature decimal(4,1),
    temperature_unit text DEFAULT 'C' CHECK (temperature_unit IN ('C', 'F')),
    weight decimal(5,2),
    weight_unit text DEFAULT 'kg' CHECK (weight_unit IN ('kg', 'lbs')),
    height decimal(5,2),
    height_unit text DEFAULT 'cm' CHECK (height_unit IN ('cm', 'in')),
    bmi decimal(4,1),
    oxygen_saturation integer,
    respiratory_rate integer,
    blood_glucose decimal(5,1),
    blood_glucose_unit text DEFAULT 'mg/dL' CHECK (blood_glucose_unit IN ('mg/dL', 'mmol/L')),
    notes text,
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for vital_signs
CREATE INDEX IF NOT EXISTS vital_signs_user_id_idx ON public.vital_signs(user_id);
CREATE INDEX IF NOT EXISTS vital_signs_measurement_date_idx ON public.vital_signs(measurement_date);

-- Enable RLS for vital_signs
ALTER TABLE public.vital_signs ENABLE ROW LEVEL SECURITY;

-- Create policies for vital_signs
CREATE POLICY "Users can view their own vital signs" ON public.vital_signs
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own vital signs" ON public.vital_signs
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own vital signs" ON public.vital_signs
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own vital signs" ON public.vital_signs
    FOR DELETE USING (auth.uid() = user_id);

-- Create user_health_profile table for PHR
CREATE TABLE IF NOT EXISTS public.user_health_profile (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL UNIQUE,
    date_of_birth date,
    gender text CHECK (gender IN ('male', 'female', 'other', 'prefer_not_to_say')),
    blood_type text CHECK (blood_type IN ('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-')),
    allergies text[],
    medications text[],
    chronic_conditions text[],
    family_history jsonb,
    emergency_contact_name text,
    emergency_contact_phone text,
    emergency_contact_relationship text,
    medical_insurance_provider text,
    medical_insurance_id text,
    primary_care_physician text,
    primary_care_phone text,
    smoking_status text CHECK (smoking_status IN ('never', 'former', 'current')),
    alcohol_consumption text CHECK (alcohol_consumption IN ('none', 'occasional', 'moderate', 'heavy')),
    exercise_frequency text CHECK (exercise_frequency IN ('none', 'rare', 'weekly', 'daily')),
    dietary_restrictions text[],
    created_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS for user_health_profile
ALTER TABLE public.user_health_profile ENABLE ROW LEVEL SECURITY;

-- Create policies for user_health_profile
CREATE POLICY "Users can view their own health profile" ON public.user_health_profile
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own health profile" ON public.user_health_profile
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own health profile" ON public.user_health_profile
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own health profile" ON public.user_health_profile
    FOR DELETE USING (auth.uid() = user_id);

-- Create health_data_audit table for audit logging
CREATE TABLE IF NOT EXISTS public.health_data_audit (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
    action text NOT NULL CHECK (action IN ('create', 'read', 'update', 'delete')),
    table_name text NOT NULL,
    record_id uuid NOT NULL,
    old_values jsonb,
    new_values jsonb,
    ip_address inet,
    user_agent text,
    performed_by uuid REFERENCES auth.users(id),
    performed_at timestamp with time zone DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Create indexes for health_data_audit
CREATE INDEX IF NOT EXISTS health_data_audit_user_id_idx ON public.health_data_audit(user_id);
CREATE INDEX IF NOT EXISTS health_data_audit_action_idx ON public.health_data_audit(action);
CREATE INDEX IF NOT EXISTS health_data_audit_performed_at_idx ON public.health_data_audit(performed_at);

-- Enable RLS for health_data_audit
ALTER TABLE public.health_data_audit ENABLE ROW LEVEL SECURITY;

-- Create policies for health_data_audit (users can only see their own audit logs)
CREATE POLICY "Users can view their own audit logs" ON public.health_data_audit
    FOR SELECT USING (auth.uid() = user_id);

-- Create function to calculate BMI
CREATE OR REPLACE FUNCTION calculate_bmi(weight_kg decimal, height_cm decimal)
RETURNS decimal AS $$
BEGIN
    IF height_cm > 0 AND weight_kg > 0 THEN
        RETURN ROUND((weight_kg / ((height_cm / 100) * (height_cm / 100)))::numeric, 1);
    ELSE
        RETURN NULL;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create function to log health data changes
CREATE OR REPLACE FUNCTION log_health_data_change()
RETURNS TRIGGER AS $$
DECLARE
    action_type text;
    old_data jsonb;
    new_data jsonb;
BEGIN
    -- Determine action type
    IF TG_OP = 'INSERT' THEN
        action_type := 'create';
        old_data := NULL;
        new_data := row_to_json(NEW)::jsonb;
    ELSIF TG_OP = 'UPDATE' THEN
        action_type := 'update';
        old_data := row_to_json(OLD)::jsonb;
        new_data := row_to_json(NEW)::jsonb;
    ELSIF TG_OP = 'DELETE' THEN
        action_type := 'delete';
        old_data := row_to_json(OLD)::jsonb;
        new_data := NULL;
    END IF;

    -- Insert audit log
    INSERT INTO public.health_data_audit (
        user_id,
        action,
        table_name,
        record_id,
        old_values,
        new_values,
        performed_by
    ) VALUES (
        COALESCE(NEW.user_id, OLD.user_id),
        action_type,
        TG_TABLE_NAME,
        COALESCE(NEW.id, OLD.id),
        old_data,
        new_data,
        auth.uid()
    );

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create triggers for audit logging on health tables
CREATE TRIGGER audit_medical_history
    AFTER INSERT OR UPDATE OR DELETE ON public.medical_history
    FOR EACH ROW EXECUTE FUNCTION log_health_data_change();

CREATE TRIGGER audit_vital_signs
    AFTER INSERT OR UPDATE OR DELETE ON public.vital_signs
    FOR EACH ROW EXECUTE FUNCTION log_health_data_change();

CREATE TRIGGER audit_user_health_profile
    AFTER INSERT OR UPDATE OR DELETE ON public.user_health_profile
    FOR EACH ROW EXECUTE FUNCTION log_health_data_change();

CREATE TRIGGER audit_prescriptions
    AFTER INSERT OR UPDATE OR DELETE ON public.prescriptions
    FOR EACH ROW EXECUTE FUNCTION log_health_data_change();

CREATE TRIGGER audit_medical_records
    AFTER INSERT OR UPDATE OR DELETE ON public.medical_records
    FOR EACH ROW EXECUTE FUNCTION log_health_data_change();

-- Create triggers for updated_at on new tables
CREATE TRIGGER update_medical_history_updated_at BEFORE UPDATE ON public.medical_history
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vital_signs_updated_at BEFORE UPDATE ON public.vital_signs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_health_profile_updated_at BEFORE UPDATE ON public.user_health_profile
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions for all tables
GRANT ALL ON public.appointments TO authenticated;
GRANT ALL ON public.prescriptions TO authenticated;
GRANT ALL ON public.medical_history TO authenticated;
GRANT ALL ON public.vital_signs TO authenticated;
GRANT ALL ON public.user_health_profile TO authenticated;
GRANT ALL ON public.health_data_audit TO authenticated;
GRANT USAGE ON SCHEMA public TO authenticated;
