import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import { userProfileValidation } from '../middleware/validation';

const router = Router();

// Get user health profile
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { data, error } = await supabase
    .from('user_health_profile')
    .select('*')
    .eq('user_id', req.user.id)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      // Profile doesn't exist yet, return empty profile structure
      return res.json({
        success: true,
        data: null,
        message: 'Health profile not found, create one to get started'
      });
    }
    console.error('Error fetching health profile:', error);
    return res.status(500).json({ error: 'Failed to fetch health profile' });
  }

  res.json({
    success: true,
    data
  });
}));

// Create or update user health profile
router.post('/', userProfileValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const {
    date_of_birth,
    gender,
    blood_type,
    allergies,
    medications,
    chronic_conditions,
    family_history,
    emergency_contact_name,
    emergency_contact_phone,
    emergency_contact_relationship,
    medical_insurance_provider,
    medical_insurance_id,
    primary_care_physician,
    primary_care_phone,
    smoking_status,
    alcohol_consumption,
    exercise_frequency,
    dietary_restrictions
  } = req.body;

  // Check if profile already exists
  const { data: existingProfile } = await supabase
    .from('user_health_profile')
    .select('id')
    .eq('user_id', req.user.id)
    .single();

  const profileData = {
    user_id: req.user.id,
    date_of_birth,
    gender,
    blood_type,
    allergies: allergies || [],
    medications: medications || [],
    chronic_conditions: chronic_conditions || [],
    family_history: family_history || {},
    emergency_contact_name,
    emergency_contact_phone,
    emergency_contact_relationship,
    medical_insurance_provider,
    medical_insurance_id,
    primary_care_physician,
    primary_care_phone,
    smoking_status,
    alcohol_consumption,
    exercise_frequency,
    dietary_restrictions: dietary_restrictions || []
  };

  let result;
  if (existingProfile) {
    // Update existing profile
    const { data, error } = await supabase
      .from('user_health_profile')
      .update(profileData)
      .eq('user_id', req.user.id)
      .select()
      .single();

    if (error) {
      console.error('Error updating health profile:', error);
      return res.status(500).json({ error: 'Failed to update health profile' });
    }

    result = {
      data,
      message: 'Health profile updated successfully',
      created: false
    };
  } else {
    // Create new profile
    const { data, error } = await supabase
      .from('user_health_profile')
      .insert(profileData)
      .select()
      .single();

    if (error) {
      console.error('Error creating health profile:', error);
      return res.status(500).json({ error: 'Failed to create health profile' });
    }

    result = {
      data,
      message: 'Health profile created successfully',
      created: true
    };
  }

  res.status(result.created ? 201 : 200).json({
    success: true,
    ...result
  });
}));

// Update specific fields of health profile
router.patch('/', userProfileValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const updateData = { ...req.body };
  delete updateData.user_id; // Prevent user_id from being updated

  const { data, error } = await supabase
    .from('user_health_profile')
    .update(updateData)
    .eq('user_id', req.user.id)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Health profile not found' });
    }
    console.error('Error updating health profile:', error);
    return res.status(500).json({ error: 'Failed to update health profile' });
  }

  res.json({
    success: true,
    data,
    message: 'Health profile updated successfully'
  });
}));

// Delete user health profile
router.delete('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { error } = await supabase
    .from('user_health_profile')
    .delete()
    .eq('user_id', req.user.id);

  if (error) {
    console.error('Error deleting health profile:', error);
    return res.status(500).json({ error: 'Failed to delete health profile' });
  }

  res.json({
    success: true,
    message: 'Health profile deleted successfully'
  });
}));

// Get health profile summary (for quick access)
router.get('/summary', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { data, error } = await supabase
    .from('user_health_profile')
    .select(`
      blood_type,
      allergies,
      chronic_conditions,
      emergency_contact_name,
      emergency_contact_phone,
      primary_care_physician,
      smoking_status,
      exercise_frequency
    `)
    .eq('user_id', req.user.id)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.json({
        success: true,
        data: null,
        message: 'No health profile found'
      });
    }
    console.error('Error fetching health profile summary:', error);
    return res.status(500).json({ error: 'Failed to fetch health profile summary' });
  }

  res.json({
    success: true,
    data
  });
}));

export { router as userHealthProfileRoutes };