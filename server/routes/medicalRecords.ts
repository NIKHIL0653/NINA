import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import { medicalRecordValidation } from '../middleware/validation';

const router = Router();

// Get all medical records for authenticated user
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { data, error } = await supabase
    .from('medical_records')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });

  if (error) {
    console.error('Error fetching medical records:', error);
    return res.status(500).json({ error: 'Failed to fetch medical records' });
  }

  // Transform data to match client expectations
  const transformedRecords = data.map(record => ({
    id: record.test_data.id,
    testName: record.test_data.testName,
    testId: record.test_data.testId,
    date: record.test_data.date,
    parameters: record.test_data.parameters,
    created_at: record.created_at
  }));

  res.json({
    success: true,
    data: transformedRecords,
    count: transformedRecords.length
  });
}));

// Get specific medical record
router.get('/:recordId', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { recordId } = req.params;

  const { data, error } = await supabase
    .from('medical_records')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('test_data->>id', recordId)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Medical record not found' });
    }
    console.error('Error fetching medical record:', error);
    return res.status(500).json({ error: 'Failed to fetch medical record' });
  }

  const transformedRecord = {
    id: data.test_data.id,
    testName: data.test_data.testName,
    testId: data.test_data.testId,
    date: data.test_data.date,
    parameters: data.test_data.parameters,
    created_at: data.created_at
  };

  res.json({
    success: true,
    data: transformedRecord
  });
}));

// Create new medical record
router.post('/', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { testName, testId, date, parameters } = req.body;

  // Validation
  if (!testName || !testId || !date || !parameters) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['testName', 'testId', 'date', 'parameters']
    });
  }

  if (!Array.isArray(parameters)) {
    return res.status(400).json({ error: 'Parameters must be an array' });
  }

  const recordId = `record_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  const recordData = {
    id: recordId,
    testName,
    testId,
    date,
    parameters
  };

  const { data, error } = await supabase
    .from('medical_records')
    .insert({
      user_id: req.user.id,
      test_type: testId,
      test_data: recordData
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating medical record:', error);
    return res.status(500).json({ error: 'Failed to create medical record' });
  }

  res.status(201).json({
    success: true,
    data: {
      id: data.test_data.id,
      testName: data.test_data.testName,
      testId: data.test_data.testId,
      date: data.test_data.date,
      parameters: data.test_data.parameters,
      created_at: data.created_at
    },
    message: 'Medical record created successfully'
  });
}));

// Update medical record
router.put('/:recordId', medicalRecordValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { recordId } = req.params;
  const { testName, testId, date, parameters } = req.body;

  // Validation
  if (!testName || !testId || !date || !parameters) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['testName', 'testId', 'date', 'parameters']
    });
  }

  const recordData = {
    id: recordId,
    testName,
    testId,
    date,
    parameters
  };

  const { data, error } = await supabase
    .from('medical_records')
    .update({
      test_type: testId,
      test_data: recordData
    })
    .eq('user_id', req.user.id)
    .eq('test_data->>id', recordId)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Medical record not found' });
    }
    console.error('Error updating medical record:', error);
    return res.status(500).json({ error: 'Failed to update medical record' });
  }

  res.json({
    success: true,
    data: {
      id: data.test_data.id,
      testName: data.test_data.testName,
      testId: data.test_data.testId,
      date: data.test_data.date,
      parameters: data.test_data.parameters,
      created_at: data.created_at
    },
    message: 'Medical record updated successfully'
  });
}));

// Delete medical record
router.delete('/:recordId', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { recordId } = req.params;

  const { error } = await supabase
    .from('medical_records')
    .delete()
    .eq('user_id', req.user.id)
    .eq('test_data->>id', recordId);

  if (error) {
    console.error('Error deleting medical record:', error);
    return res.status(500).json({ error: 'Failed to delete medical record' });
  }

  res.json({
    success: true,
    message: 'Medical record deleted successfully'
  });
}));

// Get medical records by test type
router.get('/type/:testType', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { testType } = req.params;

  const { data, error } = await supabase
    .from('medical_records')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('test_type', testType)
    .order('created_at', { ascending: false });

  if (error) {
    console.error('Error fetching medical records by type:', error);
    return res.status(500).json({ error: 'Failed to fetch medical records' });
  }

  const transformedRecords = data.map(record => ({
    id: record.test_data.id,
    testName: record.test_data.testName,
    testId: record.test_data.testId,
    date: record.test_data.date,
    parameters: record.test_data.parameters,
    created_at: record.created_at
  }));

  res.json({
    success: true,
    data: transformedRecords,
    count: transformedRecords.length
  });
}));

export { router as medicalRecordsRoutes };