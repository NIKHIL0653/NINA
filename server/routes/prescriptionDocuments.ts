import { Router } from 'express';
import { supabase } from '@shared/supabase';
import { AuthenticatedRequest } from '../middleware/auth';
import { catchAsync } from '../middleware/errorHandler';
import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: async (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads/prescription-documents');
    try {
      await fs.mkdir(uploadDir, { recursive: true });
      cb(null, uploadDir);
    } catch (error) {
      cb(error as Error, uploadDir);
    }
  },
  filename: (req, file, cb) => {
    // Generate secure filename with user ID prefix
    const userId = (req as AuthenticatedRequest).user?.id || 'anonymous';
    const timestamp = Date.now();
    const randomString = crypto.randomBytes(8).toString('hex');
    const extension = path.extname(file.originalname);
    const filename = `${userId}_${timestamp}_${randomString}${extension}`;
    cb(null, filename);
  }
});

// File filter for security
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedTypes = [
    'application/pdf',
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp',
    'image/bmp'
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only PDF and image files are allowed.'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1
  }
});

// Get all prescription documents for authenticated user
router.get('/', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { status } = req.query;

  let query = supabase
    .from('prescription_documents')
    .select('*')
    .eq('user_id', req.user.id);

  if (status) {
    query = query.eq('status', status);
  }

  query = query.order('uploaded_at', { ascending: false });

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching prescription documents:', error);
    return res.status(500).json({ error: 'Failed to fetch prescription documents' });
  }

  res.json({
    success: true,
    data: data || [],
    count: data?.length || 0
  });
}));

// Upload prescription document
router.post('/', upload.single('file'), catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const { document_name, document_type } = req.body;

  // Validate required fields
  if (!document_name || !document_type) {
    // Clean up uploaded file if validation fails
    try {
      await fs.unlink(req.file.path);
    } catch (cleanupError) {
      console.error('Error cleaning up file:', cleanupError);
    }
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['document_name', 'document_type']
    });
  }

  // Validate document type
  if (!['pdf', 'image'].includes(document_type)) {
    try {
      await fs.unlink(req.file.path);
    } catch (cleanupError) {
      console.error('Error cleaning up file:', cleanupError);
    }
    return res.status(400).json({ error: 'Invalid document type. Must be "pdf" or "image"' });
  }

  // Generate file URL (relative path for serving)
  const fileUrl = `/uploads/prescription-documents/${req.file.filename}`;

  try {
    // Save document metadata to database
    const { data, error } = await supabase
      .from('prescription_documents')
      .insert({
        user_id: req.user.id,
        document_name,
        document_type,
        file_url: fileUrl,
        file_path: req.file.path,
        file_size: req.file.size,
        mime_type: req.file.mimetype,
        status: 'active'
      })
      .select()
      .single();

    if (error) {
      // Clean up uploaded file if database insert fails
      try {
        await fs.unlink(req.file.path);
      } catch (cleanupError) {
        console.error('Error cleaning up file:', cleanupError);
      }
      console.error('Error saving prescription document:', error);
      return res.status(500).json({ error: 'Failed to save prescription document' });
    }

    res.status(201).json({
      success: true,
      data,
      message: 'Prescription document uploaded successfully'
    });
  } catch (error) {
    // Clean up uploaded file if any other error occurs
    try {
      await fs.unlink(req.file.path);
    } catch (cleanupError) {
      console.error('Error cleaning up file:', cleanupError);
    }
    console.error('Error processing prescription document upload:', error);
    return res.status(500).json({ error: 'Failed to process prescription document upload' });
  }
}));

// Update prescription document status
router.patch('/:id/status', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;
  const { status } = req.body;

  if (!status || !['active', 'completed'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Must be "active" or "completed"' });
  }

  const { data, error } = await supabase
    .from('prescription_documents')
    .update({
      status,
      updated_at: new Date().toISOString()
    })
    .eq('user_id', req.user.id)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      return res.status(404).json({ error: 'Prescription document not found' });
    }
    console.error('Error updating prescription document status:', error);
    return res.status(500).json({ error: 'Failed to update prescription document status' });
  }

  res.json({
    success: true,
    data,
    message: 'Prescription document status updated successfully'
  });
}));

// Delete prescription document
router.delete('/:id', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { id } = req.params;

  // First get the document to get file path
  const { data: document, error: fetchError } = await supabase
    .from('prescription_documents')
    .select('file_path')
    .eq('user_id', req.user.id)
    .eq('id', id)
    .single();

  if (fetchError) {
    if (fetchError.code === 'PGRST116') {
      return res.status(404).json({ error: 'Prescription document not found' });
    }
    console.error('Error fetching prescription document:', fetchError);
    return res.status(500).json({ error: 'Failed to fetch prescription document' });
  }

  // Delete from database
  const { error: deleteError } = await supabase
    .from('prescription_documents')
    .delete()
    .eq('user_id', req.user.id)
    .eq('id', id);

  if (deleteError) {
    console.error('Error deleting prescription document:', deleteError);
    return res.status(500).json({ error: 'Failed to delete prescription document' });
  }

  // Delete physical file
  if (document.file_path) {
    try {
      await fs.unlink(document.file_path);
    } catch (fileError) {
      console.error('Error deleting physical file:', fileError);
      // Don't return error here as database deletion succeeded
    }
  }

  res.json({
    success: true,
    message: 'Prescription document deleted successfully'
  });
}));

// Serve uploaded files
router.get('/file/:filename', catchAsync(async (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { filename } = req.params;
  const filePath = path.join(__dirname, '../../uploads/prescription-documents', filename);

  // Verify file belongs to user by checking database
  const userId = req.user.id;
  const { data, error } = await supabase
    .from('prescription_documents')
    .select('id')
    .eq('user_id', userId)
    .eq('file_url', `/uploads/prescription-documents/${filename}`)
    .single();

  if (error || !data) {
    return res.status(404).json({ error: 'File not found or access denied' });
  }

  // Check if file exists
  try {
    await fs.access(filePath);
  } catch (error) {
    return res.status(404).json({ error: 'File not found' });
  }

  // Set appropriate headers and stream file
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const fileStream = require('fs').createReadStream(filePath);
  fileStream.pipe(res);
}));

export { router as prescriptionDocumentsRoutes };