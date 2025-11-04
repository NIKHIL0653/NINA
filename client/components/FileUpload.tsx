import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Upload,
  FileText,
  Image as ImageIcon,
  X,
  AlertTriangle,
  CheckCircle,
  Loader2,
} from 'lucide-react';
import { processFile, ProcessedFile, FileProcessingError, formatFileSize, ALLOWED_IMAGE_TYPES } from '@/lib/fileProcessing';
import { cn } from '@/lib/utils';

interface FileUploadProps {
  onFileProcessed: (processedFile: ProcessedFile) => void;
  onImageProcessed?: (imageFile: File) => void;
  onError: (error: string) => void;
  disabled?: boolean;
}

export default function FileUpload({ onFileProcessed, onImageProcessed, onError, disabled }: FileUploadProps) {
  const [uploadedFile, setUploadedFile] = useState<ProcessedFile | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onDrop = useCallback(
    async (acceptedFiles: File[]) => {
      if (disabled || isProcessing) return;

      const file = acceptedFiles[0];
      if (!file) return;

      setError(null);
      setIsProcessing(true);

      try {
        // Check if it's an image file for direct analysis
        if (ALLOWED_IMAGE_TYPES.includes(file.type) && onImageProcessed) {
          setUploadedFile({ text: '', fileName: file.name, fileType: 'image', fileSize: file.size });
          onImageProcessed(file);
        } else {
          const processedFile = await processFile(file);
          setUploadedFile(processedFile);
          onFileProcessed(processedFile);
        }
      } catch (err) {
        const errorMessage = err instanceof FileProcessingError
          ? err.message
          : 'Failed to process file. Please try again.';
        setError(errorMessage);
        onError(errorMessage);
      } finally {
        setIsProcessing(false);
      }
    },
    [disabled, isProcessing, onFileProcessed, onError]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png'],
      'image/webp': ['.webp'],
      'image/bmp': ['.bmp'],
    },
    maxFiles: 1,
    disabled: disabled || isProcessing,
    maxSize: 10 * 1024 * 1024, // 10MB
  });

  const clearFile = () => {
    setUploadedFile(null);
    setError(null);
  };

  const getFileIcon = (fileType: string) => {
    return fileType === 'pdf' ? <FileText className="w-4 h-4" /> : <ImageIcon className="w-4 h-4" />;
  };

  return (
    <div className="space-y-3 sm:space-y-4">
      {/* Upload Area */}
      <Card className={cn(
        "border-2 border-dashed transition-colors duration-200",
        isDragActive
          ? "border-blue-400 bg-blue-50 dark:bg-blue-950"
          : "border-gray-300 hover:border-blue-400",
        disabled && "opacity-50 cursor-not-allowed"
      )}>
        <CardContent className="p-4 sm:p-6">
          <div
            {...getRootProps()}
            className={cn(
              "cursor-pointer text-center",
              disabled && "cursor-not-allowed"
            )}
          >
            <input {...getInputProps()} />
            <div className="flex flex-col items-center space-y-3 sm:space-y-4">
              {isProcessing ? (
                <>
                  <Loader2 className="w-6 h-6 sm:w-8 sm:h-8 text-blue-500 animate-spin" />
                  <p className="text-xs sm:text-sm text-muted-foreground">
                    Processing file...
                  </p>
                </>
              ) : (
                <>
                  <Upload className="w-6 h-6 sm:w-8 sm:h-8 text-muted-foreground" />
                  {isDragActive ? (
                    <p className="text-xs sm:text-sm text-blue-600 dark:text-blue-400">
                      Drop the file here...
                    </p>
                  ) : (
                    <div className="space-y-1 sm:space-y-2">
                      <p className="text-xs sm:text-sm text-muted-foreground">
                        Drag & drop a medical report or click to browse
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Supports PDF and images (JPEG, PNG, WebP, BMP) up to 10MB
                      </p>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Error Display */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Uploaded File Display */}
      {uploadedFile && (
        <Card className="bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800">
          <CardContent className="p-3 sm:p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 sm:space-x-3">
                <div className="flex items-center space-x-1 sm:space-x-2">
                  {getFileIcon(uploadedFile.fileType)}
                  <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4 text-green-600" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs sm:text-sm font-medium text-green-800 dark:text-green-200 truncate">
                    {uploadedFile.fileName}
                  </p>
                  <p className="text-xs text-green-600 dark:text-green-400">
                    {formatFileSize(uploadedFile.fileSize)} • {uploadedFile.fileType.toUpperCase()}
                  </p>
                </div>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFile}
                className="h-6 w-6 sm:h-8 sm:w-8 p-0 text-green-600 hover:text-green-800 hover:bg-green-100"
              >
                <X className="w-3 h-3 sm:w-4 sm:h-4" />
              </Button>
            </div>
            <div className="mt-2 sm:mt-3">
              <Badge variant="outline" className="text-xs">
                Text extracted successfully
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Alternative Upload Button */}
      <div className="text-center">
        <Button
          variant="outline"
          size="sm"
          onClick={() => (document.querySelector('input[type="file"]') as HTMLInputElement)?.click()}
          disabled={disabled || isProcessing}
          className="text-xs sm:text-sm"
        >
          <Upload className="w-3 h-3 mr-2" />
          Browse Files
        </Button>
      </div>
    </div>
  );
}