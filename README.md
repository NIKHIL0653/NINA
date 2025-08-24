# Nina AI Healthcare Assistant 🏥

**Nina** is a cutting-edge AI-powered healthcare assistant that provides instant symptom analysis, medical record management, and personalized health insights. Built with modern web technologies and designed for both patients and healthcare professionals.

![Nina AI Healthcare Assistant](https://img.shields.io/badge/Nina-AI%20Healthcare-blue?style=for-the-badge&logo=medical&logoColor=white)

## 🛠️ Tech Stack

### 🚀 Badges
![React](https://img.shields.io/badge/React-2023-blue?style=flat-square&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-4.x-blue?style=flat-square&logo=typescript)
![Vite](https://img.shields.io/badge/Vite-Fast-blueviolet?style=flat-square&logo=vite)
![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.x-06b6d4?style=flat-square&logo=tailwindcss)
![Express](https://img.shields.io/badge/Express.js-Backend-black?style=flat-square&logo=express)
![Supabase](https://img.shields.io/badge/Supabase-BaaS-3fcf8e?style=flat-square&logo=supabase)
![Gemini AI](https://img.shields.io/badge/Gemini_AI-Google-blue?style=flat-square&logo=google)
![Netlify](https://img.shields.io/badge/Netlify-Deploy-00C7B7?style=flat-square&logo=netlify)


## 🌟 Features

### 🤖 Intelligent Symptom Analysis
- **Real-time AI Analysis**: Powered by Google's Gemini AI for accurate symptom interpretation
- **Conversational Interface**: Natural language processing for easy symptom description
- **Instant Recommendations**: Get immediate treatment suggestions and medication advice
- **Follow-up Questions**: Smart questioning system for better diagnosis accuracy

### 📊 Medical Records Management
- **Digital Record Keeping**: Store and manage medical test results with user-specific persistence
- **Multiple Test Types**: Support for CBC, Liver Function, Kidney Function, Lipid Profile, Thyroid, Blood Sugar, and more
- **Status Tracking**: Automatic classification of values as normal, high, or low with visual indicators
- **Historical Data**: View past records with detailed breakdowns and analytics
- **Professional Export**: Generate reports for healthcare providers
- **Unlimited Storage**: No restrictions on number of records stored

### 📈 Health Analytics Dashboard
- **Comprehensive Analytics**: Track health trends, test frequency, and parameter distributions
- **Health Score Calculation**: Automatic scoring based on normal parameter values
- **Activity Trends**: 30-day activity monitoring with directional indicators
- **Visual Insights**: Charts and graphs for better health data understanding

### 🎨 Modern User Experience
- **Responsive Design**: Fully optimized for desktop, tablet, and mobile devices
- **Mobile-First Approach**: Polished mobile experience with touch-friendly interfaces
- **Dark/Light Mode**: Automatic theme switching with user preference memory
- **Professional UI**: Clean, medical-grade interface inspired by healthcare platforms
- **Accessibility**: WCAG compliant design for all users

### 💰 Voluntary Support System
- **Free Core Features**: All primary functionality available without cost
- **Optional Donations**: Voluntary "Buy Me a Coffee" support system with QR code payments
- **UPI Integration**: Seamless payments for Indian users
- **No Subscription Locks**: Access to all features regardless of payment

### 🔒 Privacy & Security
- **Client-side Processing**: Sensitive data processed locally when possible
- **User-Specific Storage**: Individual localStorage keys for each user's data
- **Secure Storage**: Industry-standard encryption for user data
- **No Data Sharing**: Your health information stays private
- **HIPAA Conscious**: Built with healthcare privacy standards in mind

## 🛠️ Tech Stack

### Frontend
- **React 18** - Modern React with Hooks and Context API
- **TypeScript** - Type-safe development
- **Vite** - Lightning-fast build tool and dev server
- **TailwindCSS** - Utility-first CSS framework with custom animations
- **Radix UI** - Headless UI components for accessibility
- **React Router** - Client-side routing
- **Lucide React** - Beautiful icon library

### Backend & AI
- **Express.js** - Node.js web framework
- **Google Gemini AI** - Advanced language model for medical analysis
- **Supabase** - Backend-as-a-Service for authentication and data
- **TypeScript** - End-to-end type safety

### Development & Deployment
- **Vitest** - Fast unit testing framework
- **ESLint & Prettier** - Code quality and formatting
- **Netlify** - Deployment and hosting
- **Git** - Version control

## 🚀 Getting Started

### Prerequisites
- **Node.js** 18+ 
- **npm** or **yarn**
- **Google AI API Key** (for Gemini AI)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-username/nina-ai-healthcare.git
   cd nina-ai-healthcare
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Add your Google AI API key and other configurations
   ```

4. **Start development server**
   ```bash
   npm run dev
   ```

5. **Open in browser**
   Navigate to `http://localhost:8080`

### Environment Variables

```env
# Google AI Configuration
GOOGLE_AI_API_KEY=your_gemini_api_key_here

# Supabase Configuration (optional)
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

## 📱 Application Screenshots

### Landing Page
*Clean, professional homepage with new AI healthcare logo and mobile-optimized design*
- Hero section with clear value proposition and responsive typography
- Interactive stats showcase with mobile-friendly cards
- Healthcare professionals reviews with horizontal scrolling
- Feature highlights with medical iconography

### Chat Interface
*Conversational AI for symptom analysis*
- Real-time symptom analysis powered by Gemini AI
- Structured medical recommendations
- Professional medication suggestions
- Interactive symptom selector

### Medical Records
*Comprehensive health record management*
- Multiple test type support (10+ medical tests)
- Visual status indicators (normal/high/low) with color coding
- Detailed parameter tracking with mobile-responsive layouts
- Historical record viewing with analytics dashboard
- User-specific data persistence across sessions

### Healthcare Professional Reviews
*Trusted endorsements from medical professionals*
- Horizontal scrolling cards with 12+ professional testimonials
- Mobile-optimized single-column view
- Smooth animations and professional styling

### Settings & Profile
*User management and preferences*
- Personal health profile management
- Dark/light theme toggle
- Account management
- Voluntary donation system with QR code integration

## 🏗️ Architecture

### Project Structure
```
├── client/                 # React frontend application
│   ├── components/         # Reusable UI components
│   │   ├── ui/            # Base UI component library (Radix UI)
│   │   ├── MainLayout.tsx # Application layout wrapper
│   │   ├── RecordAnalytics.tsx # Health analytics dashboard
│   │   ├── HealthcareProfessionalsReviews.tsx # Professional testimonials
│   │   ├── MarqueeReviews.tsx # User reviews with animations
│   │   └── BuyMeCoffee.tsx # Voluntary donation component
│   ├── pages/             # Application pages/routes
│   │   ├── Index.tsx      # Landing page
│   │   ├── Chat.tsx       # AI chat interface
│   │   ├── Records.tsx    # Medical records management
│   │   ├── Login.tsx      # User authentication
│   │   ├── Register.tsx   # User registration
│   │   └── Settings.tsx   # User settings and profile
│   ├── hooks/             # Custom React hooks
│   ├── lib/               # Utility libraries and contexts
│   └── global.css         # Global styles, themes, and animations
├── server/                # Express.js backend
│   ├── routes/            # API route handlers
│   └── index.ts           # Server configuration
├── shared/                # Shared TypeScript types
└── netlify/              # Netlify deployment functions
```

### Key Design Patterns
- **Component Composition**: Modular, reusable components
- **Custom Hooks**: Encapsulated logic for common operations
- **Context Providers**: Global state management for theme and auth
- **Type Safety**: End-to-end TypeScript for reliability
- **Responsive Design**: Mobile-first, progressive enhancement
- **Animation System**: CSS-based animations for smooth user experience

## 🤖 AI Integration

### Gemini AI Features
- **Natural Language Processing**: Understands medical terminology and symptoms
- **Contextual Analysis**: Maintains conversation context for better accuracy
- **Structured Responses**: Returns formatted medical recommendations
- **Error Handling**: Robust retry logic for service reliability
- **Rate Limiting**: Intelligent request management

### Medical Accuracy
⚠️ **Important Medical Disclaimer**: Nina AI provides general health information and should not replace professional medical advice, diagnosis, or treatment. Always consult with qualified healthcare providers for medical concerns.

## 🎨 Design System

### Visual Identity
- **Logo**: Custom AI healthcare assistant logo with friendly medical theme
- **Brand Colors**: Blue gradients (#3B82F6 to #06B6D4) representing trust and healthcare
- **Typography**: Inter font family for clean, professional appearance

### Color Palette
- **Primary**: Blue gradients (#3B82F6 to #06B6D4)
- **Success**: Emerald (#10B981)
- **Warning**: Amber (#F59E0B)
- **Error**: Rose (#EF4444)
- **Neutral**: Gray scale with proper contrast ratios

### Typography
- **Primary Font**: Inter (clean, medical professional)
- **Sizes**: Responsive scale from 12px to 72px
- **Weights**: 300, 400, 500, 600, 700

### Components
- **Cards**: Elevated surfaces with subtle shadows and gradients
- **Buttons**: Gradient backgrounds with hover effects
- **Forms**: Clean inputs with validation states
- **Navigation**: Sticky headers with backdrop blur
- **Animations**: Smooth marquee scrolling and hover effects

## 📊 Recent Updates & Improvements

### Version 2.0 Features
- **New AI Healthcare Logo**: Professional logo integration across all pages
- **Enhanced Mobile Experience**: Completely redesigned mobile interface
- **Analytics Dashboard**: Comprehensive health metrics and trends
- **Unlimited Record Storage**: Removed all storage limitations
- **User-Specific Persistence**: Individual data storage per user account
- **Voluntary Donation System**: Optional support with QR code payments
- **Healthcare Professional Reviews**: Horizontal scrolling testimonials

### Mobile Optimizations
- **Responsive Typography**: Progressive text sizing for all screen sizes
- **Touch-Friendly Interface**: Larger tap targets and proper spacing
- **Single Column Reviews**: Optimized review display for mobile devices
- **Flexible Layouts**: Grid systems that adapt to screen constraints
- **Improved Navigation**: Mobile-optimized buttons and spacing

### Performance Enhancements
- **Slower Animation Speed**: Improved readability of marquee reviews
- **Optimized Images**: Better loading and display of healthcare logo
- **Local Storage Optimization**: Efficient data persistence per user
- **Component Efficiency**: Reduced re-renders and improved performance

## 🧪 Testing

```bash
# Run unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Generate coverage report
npm run test:coverage
```

## 🚀 Deployment

### Netlify (Recommended)
```bash
# Build for production
npm run build

# Deploy to Netlify
netlify deploy --prod
```

### Manual Deployment
```bash
# Build application
npm run build

# Start production server
npm start
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/your-username/nina-ai-healthcare/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-username/nina-ai-healthcare/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/nina-ai-healthcare/discussions)

**Made with ❤️ for better healthcare accessibility**

*Nina AI Healthcare Assistant - Empowering informed health decisions through AI technology*
