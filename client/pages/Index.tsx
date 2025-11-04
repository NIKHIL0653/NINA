import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useDarkMode } from "@/hooks/use-dark-mode";
import MarqueeReviews from "@/components/MarqueeReviews";
import HealthcareProfessionalsReviews from "@/components/HealthcareProfessionalsReviews";
import {
  MessageCircle,
  Heart,
  Stethoscope,
  Activity,
  BarChart3,
  TrendingUp,
  Shield,
  ChevronRight,
  Star,
  Users,
  Brain,
  Zap,
  CheckCircle,
  Clock,
  UserCheck,
  Moon,
  Sun,
  Plus,
  RefreshCw,
} from "lucide-react";

export default function Index() {
  const { isDark, toggle } = useDarkMode();

  const stats = [
    { value: "99.2%", label: "Accuracy Rate", icon: TrendingUp, color: "text-emerald-500" },
    { value: "2.3M+", label: "Users Helped", icon: Users, color: "text-blue-500" },
    { value: "< 30s", label: "Response Time", icon: Zap, color: "text-amber-500" },
    { value: "24/7", label: "Available", icon: Heart, color: "text-rose-500" },
  ];

  const features = [
    {
      icon: Brain,
      title: "AI Symptom Analysis",
      description:
        "Advanced machine learning algorithms analyze your symptoms with medical-grade precision",
    },
    {
      icon: BarChart3,
      title: "Smart Health Records",
      description:
        "Intelligent tracking and analysis of your medical records with automated insights",
    },
    {
      icon: Shield,
      title: "Privacy & Security",
      description:
        "Bank-level encryption ensures your health data remains completely private and secure",
    },
  ];

  return (
    <div className="min-h-screen bg-background transition-colors duration-300">
      {/* Navigation */}
      <nav className="border-b border-gray-200 dark:border-gray-700 bg-white/80 dark:bg-gray-900/80 backdrop-blur-md px-4 sm:px-6 py-3 sm:py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <div className="w-8 h-8 sm:w-10 sm:h-10 md:w-12 md:h-12 rounded-2xl overflow-hidden shadow-lg">
              <img
                src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                alt="NINA AI Logo"
                className="w-full h-full object-cover"
              />
            </div>
            <div>
              <h1 className="text-base sm:text-lg md:text-xl font-bold text-gray-900 dark:text-white">NINA</h1>
            </div>
          </div>
          <div className="flex items-center space-x-1 sm:space-x-2 md:space-x-3">
            {/* Dark Mode Toggle */}
            <Button
              variant="ghost"
              size="sm"
              onClick={toggle}
              className="p-1.5 sm:p-2 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
            >
              {isDark ? <Sun className="w-3 h-3 sm:w-4 sm:h-4" /> : <Moon className="w-3 h-3 sm:w-4 sm:h-4" />}
            </Button>
            <Link to="/login">
              <Button variant="ghost" size="sm" className="text-gray-600 dark:text-gray-400 text-xs sm:text-sm px-2 sm:px-3">
                Sign In
              </Button>
            </Link>
            <Link to="/register">
              <Button
                size="sm"
                className="bg-blue-400 hover:bg-blue-500 text-white shadow-lg text-xs sm:text-sm px-2 sm:px-3 md:px-4"
              >
                Get Started
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="px-4 sm:px-6 py-12 sm:py-16 md:py-20 lg:py-24">
        <div className="max-w-6xl mx-auto text-center">
          <div className="space-y-6 sm:space-y-8 md:space-y-10">
            <Badge className="bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-700 px-2 sm:px-3 md:px-4 py-1 sm:py-2 text-xs sm:text-sm font-medium">
              ✨ AI-Powered Healthcare Revolution
            </Badge>
            <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl xl:text-6xl 2xl:text-7xl font-bold text-foreground leading-tight px-2">
              Your Personal Medical AI Companion
            </h1>
            <p className="text-base sm:text-lg md:text-xl lg:text-2xl text-gray-600 dark:text-gray-300 leading-relaxed max-w-4xl mx-auto px-4">
              Get instant symptom analysis, track medical records, and receive personalized health
              insights powered by cutting-edge AI technology designed for your wellness journey.
            </p>
            <div className="flex justify-center pt-4 sm:pt-6 px-4">
              <Link to="/register" className="w-full sm:w-auto">
                <Button
                  size="lg"
                  className="w-full sm:w-auto bg-blue-400 hover:bg-blue-500 text-white px-6 sm:px-8 md:px-10 py-2.5 sm:py-3 md:py-4 rounded-2xl text-sm sm:text-base md:text-lg font-semibold shadow-lg transition-all duration-300"
                >
                  Start Free Analysis
                  <ChevronRight className="w-3 h-3 sm:w-4 sm:h-4 md:w-5 md:h-5 ml-2" />
                </Button>
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-3 md:gap-6 mt-8 sm:mt-12 md:mt-16 lg:mt-20 px-2">
            {stats.map((stat, index) => {
              const Icon = stat.icon;
              return (
                <Card
                  key={index}
                  className="bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm border-0 shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-1"
                >
                  <CardContent className="p-2 sm:p-3 md:p-4 lg:p-6 text-center">
                    <Icon className={`w-4 h-4 sm:w-6 sm:h-6 md:w-8 md:h-8 ${stat.color} mx-auto mb-1 sm:mb-2 md:mb-3`} />
                    <div className="text-lg sm:text-xl md:text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white mb-0.5 sm:mb-1">
                      {stat.value}
                    </div>
                    <div className="text-xs sm:text-sm text-gray-600 dark:text-gray-400 font-medium">{stat.label}</div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* iPhone Mockups Section */}
      <section className="px-4 sm:px-6 py-12 sm:py-16 md:py-20 lg:py-24 bg-gradient-to-br from-gray-50 to-blue-50/30 dark:from-gray-800 dark:to-blue-900/10">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-8 sm:mb-12 md:mb-16 lg:mb-20">
            <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4 md:mb-6 px-4">
              See NINA in Action
            </h2>
            <p className="text-base sm:text-lg md:text-xl text-gray-600 dark:text-gray-300 max-w-2xl mx-auto px-4">
              Experience intelligent health management across all features
            </p>
          </div>

          {/* iPhone Mockups Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 lg:gap-12 items-center justify-items-center">

            {/* Chat Feature Android */}
            <div className="w-full max-w-[280px] mx-auto">
              <div className="relative">
                {/* Android Frame */}
                <div className="bg-gray-900 rounded-[24px] p-2 shadow-2xl">
                  <div className="bg-black rounded-[20px] p-1">
                    <div className="bg-white dark:bg-gray-900 rounded-[16px] overflow-hidden h-[580px] relative">
                      {/* Screen Content */}
                      <div className="h-full flex flex-col">
                        {/* Header */}
                        <div className="bg-blue-400 px-4 py-3 flex items-center">
                          <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center mr-3">
                            <Brain className="w-4 h-4 text-white" />
                          </div>
                          <div>
                            <h3 className="text-white font-semibold text-sm">NINA AI</h3>
                            <p className="text-blue-100 text-xs">Online</p>
                          </div>
                        </div>

                        {/* Chat Messages */}
                        <div className="flex-1 p-4 space-y-4 bg-gray-50 dark:bg-gray-800">
                          <div className="flex justify-end">
                            <div className="bg-blue-500 text-white rounded-2xl rounded-br-sm p-3 max-w-[200px]">
                              <p className="text-xs">I have a headache and feel tired</p>
                            </div>
                          </div>
                          <div className="flex">
                            <div className="bg-white dark:bg-gray-700 rounded-2xl rounded-bl-sm p-3 max-w-[200px] shadow-sm">
                              <p className="text-xs text-gray-700 dark:text-gray-300">Let me help analyze your symptoms. Can you rate your pain from 1-10?</p>
                            </div>
                          </div>
                          <div className="flex justify-end">
                            <div className="bg-blue-500 text-white rounded-2xl rounded-br-sm p-3 max-w-[200px]">
                              <p className="text-xs">About 6-7</p>
                            </div>
                          </div>
                        </div>

                        {/* Input */}
                        <div className="p-3 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
                          <div className="bg-gray-100 dark:bg-gray-800 rounded-full px-3 py-2 flex items-center">
                            <span className="text-xs text-gray-500 flex-1">Type a message...</span>
                            <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center">
                              <ChevronRight className="w-3 h-3 text-white" />
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="text-center mt-6">
                  <h3 className="font-bold text-lg text-gray-900 dark:text-white mb-2">AI Chat Assistant</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Get instant symptom analysis</p>
                </div>
              </div>
            </div>

            {/* Records Feature Android */}
            <div className="w-full max-w-[280px] mx-auto">
              <div className="relative">
                {/* Android Frame */}
                <div className="bg-gray-900 rounded-[24px] p-2 shadow-2xl">
                  <div className="bg-black rounded-[20px] p-1">
                    <div className="bg-white dark:bg-gray-900 rounded-[16px] overflow-hidden h-[580px] relative">
                      {/* Screen Content */}
                      <div className="h-full flex flex-col">
                        {/* Header */}
                        <div className="bg-blue-400 px-4 py-3 flex items-center">
                          <div className="w-6 h-6 bg-white/20 rounded-lg flex items-center justify-center mr-2">
                            <img
                              src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                              alt="NINA"
                              className="w-full h-full object-cover rounded"
                            />
                          </div>
                          <h3 className="text-white font-semibold text-sm">Clinical Records</h3>
                        </div>

                        {/* Records List */}
                        <div className="flex-1 p-3 space-y-3 bg-gray-50 dark:bg-gray-800">
                          <div className="bg-white dark:bg-gray-700 rounded-xl p-3 shadow-sm">
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="font-semibold text-xs text-gray-900 dark:text-white">Blood Test</h4>
                              <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded">Aug 5</span>
                            </div>
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-600 dark:text-gray-400">Hemoglobin</span>
                                <span className="font-medium">14.2 g/dL</span>
                              </div>
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-600 dark:text-gray-400">WBC Count</span>
                                <span className="font-medium">7,200</span>
                              </div>
                            </div>
                          </div>

                          <div className="bg-white dark:bg-gray-700 rounded-xl p-3 shadow-sm">
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="font-semibold text-xs text-gray-900 dark:text-white">Vitamin D</h4>
                              <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded">Aug 4</span>
                            </div>
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-600 dark:text-gray-400">25(OH) Vitamin D</span>
                                <span className="font-medium">34 ng/mL</span>
                              </div>
                            </div>
                          </div>

                          <div className="bg-white dark:bg-gray-700 rounded-xl p-3 shadow-sm">
                            <div className="flex items-center justify-between mb-2">
                              <h4 className="font-semibold text-xs text-gray-900 dark:text-white">HbA1c Test</h4>
                              <span className="text-xs text-blue-600 bg-blue-100 px-2 py-1 rounded">Aug 4</span>
                            </div>
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-gray-600 dark:text-gray-400">HbA1c</span>
                                <span className="font-medium">5.8%</span>
                              </div>
                            </div>
                          </div>
                        </div>

                        {/* Add Button */}
                        <div className="p-3 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
                          <button className="w-full bg-blue-400 text-white rounded-xl py-2 text-sm font-semibold flex items-center justify-center">
                            <Plus className="w-4 h-4 mr-1" />
                            Add Record
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="text-center mt-6">
                  <h3 className="font-bold text-lg text-gray-900 dark:text-white mb-2">Smart Records</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Track your health data</p>
                </div>
              </div>
            </div>

            {/* News Feature Android */}
            <div className="w-full max-w-[280px] mx-auto">
              <div className="relative">
                {/* Android Frame */}
                <div className="bg-gray-900 rounded-[24px] p-2 shadow-2xl">
                  <div className="bg-black rounded-[20px] p-1">
                    <div className="bg-white dark:bg-gray-900 rounded-[16px] overflow-hidden h-[580px] relative">
                      {/* Screen Content */}
                      <div className="h-full flex flex-col">
                        {/* Header */}
                        <div className="bg-blue-400 px-4 py-3 flex items-center justify-between">
                          <div className="flex items-center">
                            <div className="w-6 h-6 bg-white/20 rounded-lg flex items-center justify-center mr-2">
                              <img
                                src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                                alt="NINA"
                                className="w-full h-full object-cover rounded"
                              />
                            </div>
                            <h3 className="text-white font-semibold text-sm">News</h3>
                          </div>
                          <button className="w-6 h-6 bg-white/20 rounded-lg flex items-center justify-center">
                            <RefreshCw className="w-3 h-3 text-white" />
                          </button>
                        </div>

                        {/* News Articles */}
                        <div className="flex-1 p-3 space-y-3 bg-gray-50 dark:bg-gray-800">
                          <div className="bg-white dark:bg-gray-700 rounded-xl overflow-hidden shadow-sm">
                            <img
                              src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
                              alt="Health News"
                              className="w-full h-20 object-cover"
                            />
                            <div className="p-3">
                              <h4 className="font-semibold text-xs text-gray-900 dark:text-white mb-1">New AI Breakthrough in Early Disease Detection</h4>
                              <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Researchers develop AI system that can detect diseases weeks before symptoms appear...</p>
                              <span className="text-xs text-blue-600 font-medium">Medical News Today</span>
                            </div>
                          </div>

                          <div className="bg-white dark:bg-gray-700 rounded-xl overflow-hidden shadow-sm">
                            <img
                              src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F79f8aec8ed8147bebbb4994b9e8da688?format=webp&width=800"
                              alt="Health News"
                              className="w-full h-20 object-cover"
                            />
                            <div className="p-3">
                              <h4 className="font-semibold text-xs text-gray-900 dark:text-white mb-1">Revolutionary Gene Therapy Shows Promise</h4>
                              <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Clinical trials demonstrate remarkable success in treating rare genetic disorders...</p>
                              <span className="text-xs text-blue-600 font-medium">Gene Therapy Research</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="text-center mt-6">
                  <h3 className="font-bold text-lg text-gray-900 dark:text-white mb-2">Health News</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Stay updated with medical breakthroughs</p>
                </div>
              </div>
            </div>
          </div>

          {/* CTA Below iPhones */}
          <div className="text-center mt-12 sm:mt-16">
            <p className="text-base sm:text-lg text-gray-600 dark:text-gray-300 mb-6 sm:mb-8">
              Experience all features on any device
            </p>
            <Link to="/register">
              <Button
                size="lg"
                className="bg-blue-400 hover:bg-blue-500 text-white px-6 sm:px-8 py-3 sm:py-4 rounded-2xl text-base sm:text-lg font-semibold shadow-lg transition-all duration-300"
              >
                Start Your Health Journey
                <ChevronRight className="w-4 h-4 sm:w-5 sm:h-5 ml-2" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="px-4 sm:px-6 py-12 sm:py-16 md:py-20">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-8 sm:mb-12 md:mb-16">
            <h2 className="text-xl sm:text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4 px-4">
              Advanced Healthcare Technology
            </h2>
            <p className="text-sm sm:text-base md:text-lg text-gray-600 dark:text-gray-300 px-4">
              Everything you need for comprehensive health management
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6 md:gap-8 px-4">
            {features.map((feature, index) => {
              const Icon = feature.icon;
              return (
                <Card key={index} className="border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 rounded-xl">
                  <CardContent className="p-4 sm:p-6 md:p-8 text-center">
                    <div className="w-10 h-10 sm:w-12 sm:h-12 md:w-16 md:h-16 bg-blue-400 rounded-xl flex items-center justify-center mx-auto mb-3 sm:mb-4 md:mb-6">
                      <Icon className="w-5 h-5 sm:w-6 sm:h-6 md:w-8 md:h-8 text-white" />
                    </div>
                    <h3 className="text-base sm:text-lg md:text-xl font-semibold text-gray-900 dark:text-white mb-2 sm:mb-3 md:mb-4">
                      {feature.title}
                    </h3>
                    <p className="text-xs sm:text-sm md:text-base text-gray-600 dark:text-gray-300 leading-relaxed">
                      {feature.description}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      {/* Reviews Marquee */}
      <section className="py-8 sm:py-12 md:py-16 bg-gradient-to-b from-white to-gray-50 dark:from-gray-900 dark:to-gray-800">
        <div className="max-w-6xl mx-auto px-4 sm:px-6">
          <div className="text-center mb-6 sm:mb-8 md:mb-12">
            <h2 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white mb-2 sm:mb-3 md:mb-4 px-4">
              Trusted by Thousands
            </h2>
            <p className="text-sm sm:text-base md:text-lg text-gray-600 dark:text-gray-300 max-w-xl mx-auto px-4">
              See what our users are saying about NINA
            </p>
          </div>
          <MarqueeReviews />
        </div>
      </section>

      {/* Healthcare Professionals Reviews */}
      <section className="px-4 sm:px-6 py-12 sm:py-16 md:py-20 lg:py-24 bg-gradient-to-r from-blue-50 to-cyan-50 dark:from-blue-900/20 dark:to-cyan-900/20">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-8 sm:mb-12 md:mb-16">
            <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4 md:mb-6 px-4">
              Trusted by Healthcare Professionals
            </h2>
            <p className="text-base sm:text-lg md:text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto px-4">
              Leading medical professionals worldwide trust NINA for accurate symptom analysis and patient education
            </p>
          </div>
          <HealthcareProfessionalsReviews />
        </div>
      </section>

      {/* CTA */}
      <section className="px-4 sm:px-6 py-12 sm:py-16 md:py-20">
        <div className="max-w-4xl mx-auto text-center">
          <div className="bg-blue-50 dark:bg-blue-900/20 rounded-xl p-4 sm:p-6 md:p-8 lg:p-12 border border-blue-200 dark:border-blue-800 mx-4">
            <h2 className="text-xl sm:text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-3 sm:mb-4 md:mb-6">
              Ready to Transform Your Healthcare?
            </h2>
            <p className="text-sm sm:text-base md:text-lg text-gray-600 dark:text-gray-300 mb-4 sm:mb-6 md:mb-8">
              Join thousands of users who trust NINA for their health
              insights
            </p>
            <Link to="/register">
              <Button
                size="lg"
                className="bg-blue-400 hover:bg-blue-500 text-white px-4 sm:px-6 md:px-8 py-2.5 sm:py-3 md:py-4 rounded-xl text-sm sm:text-base md:text-lg"
              >
                Get Started Now
                <ChevronRight className="w-3 h-3 sm:w-4 sm:h-4 md:w-5 md:h-5 ml-2" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-gray-700 px-4 sm:px-6 py-8 sm:py-12">
        <div className="max-w-7xl mx-auto text-center">
          <div className="flex items-center justify-center space-x-2 sm:space-x-3 mb-4 sm:mb-6">
            <div className="w-6 h-6 sm:w-8 sm:h-8 rounded-xl overflow-hidden">
              <img
                src="https://cdn.builder.io/api/v1/image/assets%2Fc8ab0ccd1c1f4c0983053a74f900b6ee%2F80852419a0194244b22ef22578b3e48b?format=webp&width=800"
                alt="NINA AI Logo"
                className="w-full h-full object-cover"
              />
            </div>
            <span className="text-lg sm:text-xl font-bold text-gray-900 dark:text-white">NINA</span>
          </div>
          <p className="text-sm sm:text-base text-gray-600 dark:text-gray-300 mb-6 sm:mb-8">
            Your trusted AI companion for better health management
          </p>
          <div className="border-t border-gray-200 dark:border-gray-700 pt-6 sm:pt-8 space-y-3 sm:space-y-4">
            <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400">
              © 2024 NINA. All rights reserved. This tool provides general
              health information and should not replace professional medical
              advice.
            </p>
            <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-300 font-medium">
              Built by Nikhil Choudhary
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
