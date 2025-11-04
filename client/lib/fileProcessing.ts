import { getDocument, GlobalWorkerOptions } from 'pdfjs-dist';
import { createWorker } from 'tesseract.js';

// Configure PDF.js worker
GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${'4.4.168'}/pdf.worker.min.js`;

export interface ProcessedFile {
  text: string;
  fileName: string;
  fileType: 'pdf' | 'image';
  fileSize: number;
}

// File validation constants
export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const ALLOWED_PDF_TYPES = ['application/pdf'];
export const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/bmp'];

export class FileProcessingError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'FileProcessingError';
  }
}

export function validateFile(file: File): void {
  // Check file size
  if (file.size > MAX_FILE_SIZE) {
    throw new FileProcessingError(
      `File size (${(file.size / 1024 / 1024).toFixed(2)}MB) exceeds maximum allowed size (10MB)`,
      'FILE_TOO_LARGE'
    );
  }

  // Check file type
  const allowedTypes = [...ALLOWED_PDF_TYPES, ...ALLOWED_IMAGE_TYPES];
  if (!allowedTypes.includes(file.type)) {
    throw new FileProcessingError(
      `File type ${file.type} is not supported. Please upload PDF or image files (JPEG, PNG, WebP, BMP)`,
      'INVALID_FILE_TYPE'
    );
  }

  // Additional security checks
  if (file.name.includes('..') || file.name.includes('/') || file.name.includes('\\')) {
    throw new FileProcessingError('Invalid file name', 'INVALID_FILE_NAME');
  }
}

export async function extractTextFromPDF(file: File): Promise<string> {
  try {
    const arrayBuffer = await file.arrayBuffer();
    const pdf = await getDocument({ data: new Uint8Array(arrayBuffer) }).promise;

    let fullText = '';
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const textContent = await page.getTextContent();
      const pageText = textContent.items
        .map((item: any) => item.str)
        .join(' ');
      fullText += pageText + '\n';
    }

    return fullText.trim();
  } catch (error) {
    console.error('PDF extraction error:', error);
    throw new FileProcessingError(
      'Failed to extract text from PDF. The file may be corrupted or password-protected.',
      'PDF_EXTRACTION_FAILED'
    );
  }
}

export async function extractTextFromImage(file: File): Promise<string> {
  try {
    const worker = await createWorker('eng');

    // Convert file to image URL for Tesseract
    const imageUrl = URL.createObjectURL(file);

    try {
      const { data: { text } } = await worker.recognize(imageUrl);
      return text;
    } finally {
      URL.revokeObjectURL(imageUrl);
      await worker.terminate();
    }
  } catch (error) {
    console.error('OCR extraction error:', error);
    throw new FileProcessingError(
      'Failed to extract text from image. Please ensure the image is clear and contains readable text.',
      'OCR_EXTRACTION_FAILED'
    );
  }
}

export async function processFile(file: File): Promise<ProcessedFile> {
  // Validate file first
  validateFile(file);

  let text: string;
  let fileType: 'pdf' | 'image';

  if (ALLOWED_PDF_TYPES.includes(file.type)) {
    text = await extractTextFromPDF(file);
    fileType = 'pdf';
  } else if (ALLOWED_IMAGE_TYPES.includes(file.type)) {
    text = await extractTextFromImage(file);
    fileType = 'image';
  } else {
    throw new FileProcessingError('Unsupported file type', 'UNSUPPORTED_TYPE');
  }

  // Clean up extracted text
  text = text.trim();
  if (!text) {
    throw new FileProcessingError(
      'No readable text found in the file. Please ensure the document contains text content.',
      'NO_TEXT_FOUND'
    );
  }

  return {
    text,
    fileName: file.name,
    fileType,
    fileSize: file.size,
  };
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}