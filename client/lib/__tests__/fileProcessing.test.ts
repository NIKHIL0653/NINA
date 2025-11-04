import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  validateFile,
  processFile,
  extractTextFromPDF,
  extractTextFromImage,
  MAX_FILE_SIZE,
  ALLOWED_PDF_TYPES,
  ALLOWED_IMAGE_TYPES,
  FileProcessingError
} from '../fileProcessing';

// Mock PDF.js
vi.mock('pdfjs-dist', () => ({
  getDocument: vi.fn(),
  GlobalWorkerOptions: {
    workerSrc: 'mock-worker.js'
  }
}));

// Mock Tesseract.js
vi.mock('tesseract.js', () => ({
  createWorker: vi.fn()
}));

describe('File Processing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('validateFile', () => {
    it('should validate a valid PDF file', () => {
      const validFile = new File(['test'], 'test.pdf', { type: 'application/pdf' });
      Object.defineProperty(validFile, 'size', { value: 1024 * 1024 }); // 1MB

      expect(() => validateFile(validFile)).not.toThrow();
    });

    it('should validate a valid image file', () => {
      const validFile = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      Object.defineProperty(validFile, 'size', { value: 1024 * 1024 }); // 1MB

      expect(() => validateFile(validFile)).not.toThrow();
    });

    it('should throw error for file too large', () => {
      const largeFile = new File(['test'], 'large.pdf', { type: 'application/pdf' });
      Object.defineProperty(largeFile, 'size', { value: MAX_FILE_SIZE + 1 });

      expect(() => validateFile(largeFile)).toThrow(FileProcessingError);
      expect(() => validateFile(largeFile)).toThrow('File size');
    });

    it('should throw error for invalid file type', () => {
      const invalidFile = new File(['test'], 'test.txt', { type: 'text/plain' });

      expect(() => validateFile(invalidFile)).toThrow(FileProcessingError);
      expect(() => validateFile(invalidFile)).toThrow('not supported');
    });

    it('should throw error for dangerous filename', () => {
      const dangerousFile = new File(['test'], '../dangerous.pdf', { type: 'application/pdf' });

      expect(() => validateFile(dangerousFile)).toThrow(FileProcessingError);
      expect(() => validateFile(dangerousFile)).toThrow('Invalid file name');
    });
  });

  describe('extractTextFromPDF', () => {
    it('should extract text from PDF successfully', async () => {
      const mockPdf = {
        numPages: 1,
        getPage: vi.fn().mockResolvedValue({
          getTextContent: vi.fn().mockResolvedValue({
            items: [
              { str: 'Hello ' },
              { str: 'World' }
            ]
          })
        })
      };

      const { getDocument } = await import('pdfjs-dist');
      vi.mocked(getDocument).mockReturnValue({
        promise: Promise.resolve(mockPdf)
      } as any);

      const file = new File(['test'], 'test.pdf', { type: 'application/pdf' });
      // Mock arrayBuffer method for Node.js environment
      Object.defineProperty(file, 'arrayBuffer', {
        value: vi.fn().mockResolvedValue(new ArrayBuffer(8))
      });

      const result = await extractTextFromPDF(file);

      expect(result.trim()).toBe('Hello World');
    });

    it('should handle PDF extraction errors', async () => {
      const { getDocument } = await import('pdfjs-dist');
      vi.mocked(getDocument).mockReturnValue({
        promise: Promise.reject(new Error('PDF error'))
      } as any);

      const file = new File(['test'], 'test.pdf', { type: 'application/pdf' });
      // Mock arrayBuffer method for Node.js environment
      Object.defineProperty(file, 'arrayBuffer', {
        value: vi.fn().mockResolvedValue(new ArrayBuffer(8))
      });

      await expect(extractTextFromPDF(file)).rejects.toThrow(FileProcessingError);
    });
  });

  describe('extractTextFromImage', () => {
    it('should extract text from image successfully', async () => {
      const mockWorker = {
        recognize: vi.fn().mockResolvedValue({
          data: { text: 'Extracted text from image' }
        }),
        terminate: vi.fn().mockResolvedValue(undefined)
      };

      const { createWorker } = await import('tesseract.js');
      vi.mocked(createWorker).mockResolvedValue(mockWorker as any);

      // Mock URL.createObjectURL and revokeObjectURL
      global.URL.createObjectURL = vi.fn().mockReturnValue('mock-url');
      global.URL.revokeObjectURL = vi.fn();

      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      const result = await extractTextFromImage(file);

      expect(result).toBe('Extracted text from image');
      expect(mockWorker.terminate).toHaveBeenCalled();
      expect(global.URL.revokeObjectURL).toHaveBeenCalledWith('mock-url');
    });

    it('should handle OCR errors', async () => {
      const mockWorker = {
        recognize: vi.fn().mockRejectedValue(new Error('OCR failed')),
        terminate: vi.fn().mockResolvedValue(undefined)
      };

      const { createWorker } = await import('tesseract.js');
      vi.mocked(createWorker).mockResolvedValue(mockWorker as any);

      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' });

      await expect(extractTextFromImage(file)).rejects.toThrow(FileProcessingError);
    });
  });

  describe('processFile', () => {
    it('should process PDF file successfully', async () => {
      const mockPdf = {
        numPages: 1,
        getPage: vi.fn().mockResolvedValue({
          getTextContent: vi.fn().mockResolvedValue({
            items: [{ str: 'PDF content' }]
          })
        })
      };

      const { getDocument } = await import('pdfjs-dist');
      vi.mocked(getDocument).mockReturnValue({
        promise: Promise.resolve(mockPdf)
      } as any);

      const file = new File(['test'], 'test.pdf', { type: 'application/pdf' });
      // Mock arrayBuffer method for Node.js environment
      Object.defineProperty(file, 'arrayBuffer', {
        value: vi.fn().mockResolvedValue(new ArrayBuffer(8))
      });

      const result = await processFile(file);

      expect(result).toEqual({
        text: 'PDF content',
        fileName: 'test.pdf',
        fileType: 'pdf',
        fileSize: 4
      });
    });

    it('should process image file successfully', async () => {
      const mockWorker = {
        recognize: vi.fn().mockResolvedValue({
          data: { text: 'Image text' }
        }),
        terminate: vi.fn().mockResolvedValue(undefined)
      };

      const { createWorker } = await import('tesseract.js');
      vi.mocked(createWorker).mockResolvedValue(mockWorker as any);

      global.URL.createObjectURL = vi.fn().mockReturnValue('mock-url');
      global.URL.revokeObjectURL = vi.fn();

      const file = new File(['test'], 'test.jpg', { type: 'image/jpeg' });
      const result = await processFile(file);

      expect(result).toEqual({
        text: 'Image text',
        fileName: 'test.jpg',
        fileType: 'image',
        fileSize: 4
      });
    });

    it('should throw error when no text found', async () => {
      const mockPdf = {
        numPages: 1,
        getPage: vi.fn().mockResolvedValue({
          getTextContent: vi.fn().mockResolvedValue({
            items: []
          })
        })
      };

      const { getDocument } = await import('pdfjs-dist');
      vi.mocked(getDocument).mockReturnValue({
        promise: Promise.resolve(mockPdf)
      } as any);

      const file = new File([''], 'empty.pdf', { type: 'application/pdf' });
      // Mock arrayBuffer method for Node.js environment
      Object.defineProperty(file, 'arrayBuffer', {
        value: vi.fn().mockResolvedValue(new ArrayBuffer(8))
      });

      await expect(processFile(file)).rejects.toThrow(FileProcessingError);
      await expect(processFile(file)).rejects.toThrow('No readable text found');
    });
  });
});