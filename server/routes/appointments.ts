import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import { appointmentValidation } from '../middleware/validation';

const router = Router();

// Get all appointments for authenticated user
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { status, upcoming } = req.query;

  let query = supabase
    .from('appointments')
    .select('*')
    .eq('user_id', req.user.id);

  if (status) {
    query = query.eq('status', status);
  }

  if (upcoming === 'true') {
    query = query
      .gte('appointment_date', new Date().toISOString())
      .eq('status', 'scheduled')
      .order('appointment_date', { ascending: true });
  } else {
    query = query.order('appointment_date', { ascending: false });
  }

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching appointments:', error);
    return res.status(500).json({ error: 'Failed to fetch appointments' });
  }

  res.json({
    success: true,
    data,
    count: data.length
  });
}));

// Get specific appointment
router.get('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { data, error } = await supabase
    .from('appointments')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('id', id)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    console.error('Error fetching appointment:', error);
    return res.status(500).json({ error: 'Failed to fetch appointment' });
  }

  res.json({
    success: true,
    data
  });
}));

// Create new appointment
router.post('/', appointmentValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const {
    provider_name,
    provider_specialty,
    appointment_date,
    appointment_type
  } = req.body;

  // Validation
  if (!provider_name || !appointment_date || !appointment_type) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['provider_name', 'appointment_date', 'appointment_type']
    });
  }

  // Validate appointment date is in the future
  const appointmentDate = new Date(appointment_date);
  if (appointmentDate <= new Date()) {
    return res.status(400).json({ error: 'Appointment date must be in the future' });
  }

  const { data, error } = await supabase
    .from('appointments')
    .insert({
      user_id: req.user.id,
      provider_name,
      provider_specialty,
      appointment_date,
      appointment_type,
      status: 'scheduled'
    })
    .select()
    .single();

  if (error) {
    console.error('Error creating appointment:', error);
    return res.status(500).json({ error: 'Failed to create appointment' });
  }

  res.status(201).json({
    success: true,
    data,
    message: 'Appointment created successfully'
  });
}));

// Update appointment
router.put('/:id', appointmentValidation, catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const {
    provider_name,
    provider_specialty,
    appointment_date,
    appointment_type,
    status
  } = req.body;

  // Validation
  if (!provider_name || !appointment_date || !appointment_type) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['provider_name', 'appointment_date', 'appointment_type']
    });
  }

  const updateData: any = {
    provider_name,
    provider_specialty,
    appointment_date,
    appointment_type
  };

  if (status) {
    updateData.status = status;
  }

  const { data, error } = await supabase
    .from('appointments')
    .update(updateData)
    .eq('user_id', req.user.id)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    console.error('Error updating appointment:', error);
    return res.status(500).json({ error: 'Failed to update appointment' });
  }

  res.json({
    success: true,
    data,
    message: 'Appointment updated successfully'
  });
}));

// Delete appointment
router.delete('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  const { error } = await supabase
    .from('appointments')
    .delete()
    .eq('user_id', req.user.id)
    .eq('id', id);

  if (error) {
    console.error('Error deleting appointment:', error);
    return res.status(500).json({ error: 'Failed to delete appointment' });
  }

  res.json({
    success: true,
    message: 'Appointment deleted successfully'
  });
}));

// Get appointments by date range
router.get('/range/:startDate/:endDate', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { startDate, endDate } = req.params;

  const { data, error } = await supabase
    .from('appointments')
    .select('*')
    .eq('user_id', req.user.id)
    .gte('appointment_date', startDate)
    .lte('appointment_date', endDate)
    .order('appointment_date', { ascending: true });

  if (error) {
    console.error('Error fetching appointments by date range:', error);
    return res.status(500).json({ error: 'Failed to fetch appointments' });
  }

  res.json({
    success: true,
    data,
    count: data.length
  });
}));

export { router as appointmentsRoutes };