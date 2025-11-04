import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import { medicalRecordValidation } from '../middleware/validation';

const router = Router();

// Get all medical history for authenticated user
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { status, condition } = req.query;

  let query = supabase
    .from('medical_history')
    .select('*')
    .eq('user_id', req.user.id)
    .order('diagnosis_date', { ascending: false });

  if (status) {
    query = query.eq('status', status);
  }

  if (condition) {
    query = query.ilike('condition_name', `%${condition}%`);
  }

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching medical history:', error);
    return res.status(500).json({ error: 'Failed to fetch medical history' });
  }

  res.json({
    success: true,
    data,
    count: data.length
  });
}));

// Get specific medical history record
router.get('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { data, error } = await supabase
    .from('medical_history')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('id', id)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Medical history record not found' });
    }
    console.error('Error fetching medical history:', error);
    return res.status(500).json({ error: 'Failed to fetch medical history record' });
  }

  res.json({
    success: true,
    data
  });
}));

// Create new medical history record
router.post('/', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const {
    condition_name,
    diagnosis_date,
    icd_code,
    severity,
    status,
    treating_physician,
    treatment_notes,
    symptoms,
    complications
  } = req.body;

  // Validation
  if (!condition_name || !diagnosis_date) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['condition_name', 'diagnosis_date']
    });
  }

  const { data, error } = await supabase
    .from('medical_history')
    .insert({
      user_id: req.user.id,
      condition_name,
      diagnosis_date,
      icd_code,
      severity,
      status: status || 'active',
      treating_physician,
      treatment_notes,
      symptoms,
      complications
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating medical history record:', error);
    return res.status(500).json({ error: 'Failed to create medical history record' });
  }

  res.status(201).json({
    success: true,
    data,
    message: 'Medical history record created successfully'
  });
}));

// Update medical history record
router.put('/:id', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const {
    condition_name,
    diagnosis_date,
    icd_code,
    severity,
    status,
    treating_physician,
    treatment_notes,
    symptoms,
    complications
  } = req.body;

  // Validation
  if (!condition_name || !diagnosis_date) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['condition_name', 'diagnosis_date']
    });
  }

  const { data, error } = await supabase
    .from('medical_history')
    .update({
      condition_name,
      diagnosis_date,
      icd_code,
      severity,
      status,
      treating_physician,
      treatment_notes,
      symptoms,
      complications
    })
    .eq('user_id', req.user.id)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Medical history record not found' });
    }
    console.error('Error updating medical history record:', error);
    return res.status(500).json({ error: 'Failed to update medical history record' });
  }

  res.json({
    success: true,
    data,
    message: 'Medical history record updated successfully'
  });
}));

// Delete medical history record
router.delete('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { error } = await supabase
    .from('medical_history')
    .delete()
    .eq('user_id', req.user.id)
    .eq('id', id);

  if (error) {
    console.error('Error deleting medical history record:', error);
    return res.status(500).json({ error: 'Failed to delete medical history record' });
  }

  res.json({
    success: true,
    message: 'Medical history record deleted successfully'
  });
}));

// Get medical history by date range
router.get('/range/:startDate/:endDate', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { startDate, endDate } = req.params;

  const { data, error } = await supabase
    .from('medical_history')
    .select('*')
    .eq('user_id', req.user.id)
    .gte('diagnosis_date', startDate)
    .lte('diagnosis_date', endDate)
    .order('diagnosis_date', { ascending: false });

  if (error) {
    console.error('Error fetching medical history by date range:', error);
    return res.status(500).json({ error: 'Failed to fetch medical history' });
  }

  res.json({
    success: true,
    data,
    count: data.length
  });
}));

export { router as medicalHistoryRoutes };