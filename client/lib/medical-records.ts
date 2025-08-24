import { supabase } from "@shared/supabase";

// Test function to check if the table exists
export const testDatabaseConnection = async () => {
  try {
    console.log("Checking medical records database...");
    const { data, error } = await supabase
      .from("medical_records")
      .select("id")
      .limit(1);

    if (error) {
      // Check if it's a "table doesn't exist" error
      if (error.message && error.message.includes('relation "public.medical_records" does not exist')) {
        console.log("Medical records table not found - using localStorage for data storage");
        return {
          success: false,
          error: "Database table not created yet",
          needsSetup: true
        };
      }

      console.warn("Database test failed:", error.message || error);
      return { success: false, error: error.message || String(error) };
    }

    console.log("Database connection successful");
    return { success: true };
  } catch (error) {
    console.warn("Database connection test error:", error instanceof Error ? error.message : String(error));
    return { success: false, error: error instanceof Error ? error.message : String(error) };
  }
};

export interface MedicalRecord {
  id: string;
  testName: string;
  testId: string;
  date: string;
  parameters: {
    name: string;
    unit: string;
    normalRange: string;
    value: string;
    status?: "normal" | "high" | "low";
  }[];
}

export const saveMedicalRecord = async (userId: string, record: MedicalRecord) => {
  try {
    console.log("Saving medical record for user:", userId);

    const { data, error } = await supabase
      .from("medical_records")
      .insert({
        user_id: userId,
        test_type: record.testId,
        test_data: {
          id: record.id,
          testName: record.testName,
          testId: record.testId,
          date: record.date,
          parameters: record.parameters,
        },
      });

    if (error) {
      // Fallback to localStorage
      if (error.message && error.message.includes('relation "public.medical_records" does not exist')) {
        console.log("Database table not available - saving to local storage");
      } else {
        console.warn("Database unavailable, saving to local storage:", error.message || error);
      }

      const existingRecords = loadFromLocalStorage(userId);
      const updatedRecords = [record, ...existingRecords];
      saveToLocalStorage(userId, updatedRecords);

      return { success: true, data: null, fallback: true };
    }

    console.log("Successfully saved medical record:", data);
    return { success: true, data };
  } catch (error) {
    console.error("Unexpected error saving medical record:", error instanceof Error ? error.message : String(error), error);

    // Fallback to localStorage
    console.log("Using localStorage fallback due to error");
    try {
      const existingRecords = loadFromLocalStorage(userId);
      const updatedRecords = [record, ...existingRecords];
      saveToLocalStorage(userId, updatedRecords);
      return { success: true, data: null, fallback: true };
    } catch (fallbackError) {
      return { success: false, error: "Failed to save to both database and localStorage" };
    }
  }
};

export const loadMedicalRecords = async (userId: string): Promise<MedicalRecord[]> => {
  try {
    console.log("Loading medical records for user:", userId);

    const { data, error } = await supabase
      .from("medical_records")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });

    if (error) {
      // Check if table doesn't exist - this is expected and not an error
      if (error.message && error.message.includes('relation "public.medical_records" does not exist')) {
        console.log("Database table not available - loading records from local storage");
      } else {
        console.warn("Database unavailable, using local storage:", error.message || error);
      }

      return loadFromLocalStorage(userId);
    }

    console.log("Loaded medical records data:", data);

    if (!data || data.length === 0) {
      console.log("No medical records found in database, checking localStorage");
      return loadFromLocalStorage(userId);
    }

    // Transform the data back to the expected format
    const transformedRecords = data.map((record) => {
      try {
        return {
          id: record.test_data.id,
          testName: record.test_data.testName,
          testId: record.test_data.testId,
          date: record.test_data.date,
          parameters: record.test_data.parameters,
        };
      } catch (transformError) {
        console.error("Error transforming record:", record, transformError);
        return null;
      }
    }).filter(record => record !== null) as MedicalRecord[];

    console.log("Successfully transformed records:", transformedRecords);
    return transformedRecords;
  } catch (error) {
    console.error("Unexpected error loading medical records:", error instanceof Error ? error.message : String(error), error);
    // Fallback to localStorage
    return loadFromLocalStorage(userId);
  }
};

// Fallback localStorage functions
const loadFromLocalStorage = (userId: string): MedicalRecord[] => {
  try {
    const savedRecordsData = localStorage.getItem(`medicalRecords_${userId}`);
    if (savedRecordsData) {
      const parsedRecords = JSON.parse(savedRecordsData);
      console.log("Loaded records from localStorage:", parsedRecords);
      return parsedRecords;
    }
  } catch (error) {
    console.error("Error loading from localStorage:", error);
  }
  return [];
};

const saveToLocalStorage = (userId: string, records: MedicalRecord[]) => {
  try {
    localStorage.setItem(`medicalRecords_${userId}`, JSON.stringify(records));
    console.log("Saved records to localStorage");
  } catch (error) {
    console.error("Error saving to localStorage:", error);
  }
};

export const deleteMedicalRecord = async (userId: string, recordId: string) => {
  try {
    console.log("Deleting medical record:", recordId);

    const { error } = await supabase
      .from("medical_records")
      .delete()
      .eq("user_id", userId)
      .eq("test_data->>id", recordId);

    if (error) {
      // If table doesn't exist, handle deletion from localStorage
      if (error.message && error.message.includes('relation "public.medical_records" does not exist')) {
        console.log("Database table not available - deleting from local storage");
        const existingRecords = loadFromLocalStorage(userId);
        const updatedRecords = existingRecords.filter(record => record.id !== recordId);
        saveToLocalStorage(userId, updatedRecords);
        return { success: true, fallback: true };
      }

      console.warn("Database unavailable, deleting from local storage:", error.message || error);
      const existingRecords = loadFromLocalStorage(userId);
      const updatedRecords = existingRecords.filter(record => record.id !== recordId);
      saveToLocalStorage(userId, updatedRecords);
      return { success: true, fallback: true };
    }

    console.log("Successfully deleted medical record from database");
    return { success: true };
  } catch (error) {
    console.error("Unexpected error deleting medical record:", error instanceof Error ? error.message : String(error));

    // Fallback to localStorage delete
    try {
      const existingRecords = loadFromLocalStorage(userId);
      const updatedRecords = existingRecords.filter(record => record.id !== recordId);
      saveToLocalStorage(userId, updatedRecords);
      return { success: true, fallback: true };
    } catch (fallbackError) {
      return { success: false, error: "Failed to delete from both database and localStorage" };
    }
  }
};
