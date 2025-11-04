import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import { medicalRecordValidation } from '../middleware/validation';

const router = Router();

// Get all vital signs for authenticated user
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { limit = '50', offset = '0', startDate, endDate } = req.query;

  let query = supabase
    .from('vital_signs')
    .select('*')
    .eq('user_id', req.user.id)
    .order('measurement_date', { ascending: false })
    .range(parseInt(offset as string), parseInt(offset as string) + parseInt(limit as string) - 1);

  if (startDate && endDate) {
    query = query
      .gte('measurement_date', startDate)
      .lte('measurement_date', endDate);
  }

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching vital signs:', error);
    return res.status(500).json({ error: 'Failed to fetch vital signs' });
  }

  res.json({
    success: true,
    data,
    count: data.length,
    pagination: {
      limit: parseInt(limit as string),
      offset: parseInt(offset as string)
    }
  });
}));

// Get specific vital signs record
router.get('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { data, error } = await supabase
    .from('vital_signs')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('id', id)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Vital signs record not found' });
    }
    console.error('Error fetching vital signs:', error);
    return res.status(500).json({ error: 'Failed to fetch vital signs record' });
  }

  res.json({
    success: true,
    data
  });
}));

// Create new vital signs record
router.post('/', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const {
    measurement_date,
    systolic_bp,
    diastolic_bp,
    heart_rate,
    temperature,
    temperature_unit = 'C',
    weight,
    weight_unit = 'kg',
    height,
    height_unit = 'cm',
    oxygen_saturation,
    respiratory_rate,
    blood_glucose,
    blood_glucose_unit = 'mg/dL',
    notes
  } = req.body;

  // Calculate BMI if weight and height are provided
  let bmi = null;
  if (weight && height && weight_unit === 'kg' && height_unit === 'cm') {
    bmi = Math.round((weight / ((height / 100) ** 2)) * 10) / 10;
  }

  const { data, error } = await supabase
    .from('vital_signs')
    .insert({
      user_id: req.user.id,
      measurement_date: measurement_date || new Date().toISOString(),
      systolic_bp,
      diastolic_bp,
      heart_rate,
      temperature,
      temperature_unit,
      weight,
      weight_unit,
      height,
      height_unit,
      bmi,
      oxygen_saturation,
      respiratory_rate,
      blood_glucose,
      blood_glucose_unit,
      notes
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating vital signs record:', error);
    return res.status(500).json({ error: 'Failed to create vital signs record' });
  }

  res.status(201).json({
    success: true,
    data,
    message: 'Vital signs record created successfully'
  });
}));

// Update vital signs record
router.put('/:id', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const {
    measurement_date,
    systolic_bp,
    diastolic_bp,
    heart_rate,
    temperature,
    temperature_unit,
    weight,
    weight_unit,
    height,
    height_unit,
    oxygen_saturation,
    respiratory_rate,
    blood_glucose,
    blood_glucose_unit,
    notes
  } = req.body;

  // Calculate BMI if weight and height are provided
  let bmi = null;
  if (weight && height && weight_unit === 'kg' && height_unit === 'cm') {
    bmi = Math.round((weight / ((height / 100) ** 2)) * 10) / 10;
  }

  const { data, error } = await supabase
    .from('vital_signs')
    .update({
      measurement_date,
      systolic_bp,
      diastolic_bp,
      heart_rate,
      temperature,
      temperature_unit,
      weight,
      weight_unit,
      height,
      height_unit,
      bmi,
      oxygen_saturation,
      respiratory_rate,
      blood_glucose,
      blood_glucose_unit,
      notes
    })
    .eq('user_id', req.user.id)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Vital signs record not found' });
    }
    console.error('Error updating vital signs record:', error);
    return res.status(500).json({ error: 'Failed to update vital signs record' });
  }

  res.json({
    success: true,
    data,
    message: 'Vital signs record updated successfully'
  });
}));

// Delete vital signs record
router.delete('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { error } = await supabase
    .from('vital_signs')
    .delete()
    .eq('user_id', req.user.id)
    .eq('id', id);

  if (error) {
    console.error('Error deleting vital signs record:', error);
    return res.status(500).json({ error: 'Failed to delete vital signs record' });
  }

  res.json({
    success: true,
    message: 'Vital signs record deleted successfully'
  });
}));

// Get latest vital signs
router.get('/latest/summary', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { data, error } = await supabase
    .from('vital_signs')
    .select('*')
    .eq('user_id', req.user.id)
    .order('measurement_date', { ascending: false })
    .limit(1)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.json({
        success: true,
        data: null,
        message: 'No vital signs records found'
      });
    }
    console.error('Error fetching latest vital signs:', error);
    return res.status(500).json({ error: 'Failed to fetch latest vital signs' });
  }

  res.json({
    success: true,
    data
  });
}));

// Get vital signs trends (last 30 days)
router.get('/trends/recent', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  const { data, error } = await supabase
    .from('vital_signs')
    .select('*')
    .eq('user_id', req.user.id)
    .gte('measurement_date', thirtyDaysAgo.toISOString())
    .order('measurement_date', { ascending: true });

  if (error) {
    console.error('Error fetching vital signs trends:', error);
    return res.status(500).json({ error: 'Failed to fetch vital signs trends' });
  }

  res.json({
    success: true,
    data,
    count: data.length
  });
}));

export { router as vitalSignsRoutes };