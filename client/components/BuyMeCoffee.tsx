import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Coffee,
  Download,
  Heart,
  QrCode,
  Share,
} from "lucide-react";

export default function BuyMeCoffee() {
  const [showQR, setShowQR] = useState(false);

  const downloadQRCode = () => {
    const link = document.createElement('a');
    link.href = "https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F7a5b5ae412284dcf8819c5b981c3f9e0?format=webp&width=800";
    link.download = "nina-ai-payment-qr.png";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <Card className="shadow-md border-l-4 border-l-orange-500 bg-gradient-to-r from-orange-50 to-amber-50 dark:from-orange-900/20 dark:to-amber-900/20">
      <CardHeader>
        <CardTitle className="flex items-center space-x-2">
          <Coffee className="w-6 h-6 text-orange-500" />
          <span>Support NINA Development</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-4">
          <p className="text-gray-700 dark:text-gray-300 leading-relaxed">
            If NINA has been helpful in your healthcare journey, consider supporting our development! 
            Your contribution helps us improve the AI, add new features, and keep the service running.
          </p>
          
          <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
            <Heart className="w-4 h-4 text-red-500" />
            <span>Every contribution, no matter how small, makes a difference!</span>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <Dialog open={showQR} onOpenChange={setShowQR}>
            <DialogTrigger asChild>
              <Button 
                className="bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-600 hover:to-amber-600 text-white font-semibold"
                size="lg"
              >
                <QrCode className="w-5 h-5 mr-2" />
                Scan QR to Pay
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-md">
              <DialogHeader>
                <DialogTitle className="text-center text-xl font-bold">
                  Support NINA AI ☕
                </DialogTitle>
              </DialogHeader>
              
              <div className="space-y-6">
                <div className="text-center">
                  <p className="text-gray-600 dark:text-gray-400 mb-4">
                    Scan with any UPI app to contribute any amount
                  </p>
                </div>
                
                {/* QR Code */}
                <div className="flex flex-col items-center space-y-4">
                  <div className="bg-white p-4 rounded-xl shadow-lg border-2 border-orange-200">
                    <img 
                      src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F7a5b5ae412284dcf8819c5b981c3f9e0?format=webp&width=800"
                      alt="Support NINA AI - Payment QR Code"
                      className="w-64 h-64 object-contain"
                    />
                  </div>
                  
                  <div className="text-center space-y-2">
                    <div className="bg-gray-100 dark:bg-gray-800 p-2 rounded-lg">
                      <p className="font-mono text-sm text-gray-700 dark:text-gray-300">
                        UPI ID: nikhil0653@okhdfcbank
                      </p>
                    </div>
                    <p className="text-xs text-gray-500">
                      Pay any amount that feels right to you
                    </p>
                  </div>
                </div>
                
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                  <p className="text-sm text-green-800 dark:text-green-200 text-center">
                    <strong>Thank you!</strong> Your support helps keep NINA AI free and accessible to everyone.
                  </p>
                </div>
              </div>
            </DialogContent>
          </Dialog>

          <Button 
            variant="outline" 
            onClick={downloadQRCode}
            className="border-orange-300 text-orange-600 hover:bg-orange-50 dark:border-orange-600 dark:text-orange-400 dark:hover:bg-orange-900/20"
          >
            <Download className="w-5 h-5 mr-2" />
            Download QR
          </Button>
        </div>

        <div className="text-xs text-gray-500 dark:text-gray-400 border-t pt-4">
          <p>
            <strong>Note:</strong> This is completely optional. NINA will always remain free to use. 
            Your contributions help us improve and maintain the service for everyone.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
