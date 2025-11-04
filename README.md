# NINA - AI Healthcare Assistant

A comprehensive healthcare management system with AI-powered medical assistance, built for production use with HIPAA compliance considerations.

## 🚀 Features

### Core Healthcare Features
- **AI Medical Chat**: Conversational AI assistant for symptom analysis and health guidance
- **Medical Records Management**: Secure storage and management of medical test results
- **Appointment Scheduling**: Track and manage healthcare appointments
- **Prescription Management**: Monitor medications with expiration alerts
- **Emergency Contacts**: Maintain critical contact information for emergencies

### Security & Compliance
- **HIPAA-Ready Architecture**: Designed with healthcare privacy regulations in mind
- **End-to-End Encryption**: Sensitive data protection
- **Audit Logging**: Comprehensive activity tracking for compliance
- **Role-Based Access Control**: Secure user permissions
- **Rate Limiting**: Protection against abuse and DoS attacks

### Technical Features
- **Real-time Health Monitoring**: System health checks and performance monitoring
- **File Processing**: OCR and PDF text extraction for medical documents
- **Cross-Platform**: Responsive web application
- **Offline Support**: Local storage fallback for critical features

## 🏗️ Architecture

### Backend (Node.js/Express)
- **Security**: Helmet, CORS, rate limiting, input validation
- **Database**: Supabase (PostgreSQL) with Row Level Security
- **Authentication**: JWT-based auth with Supabase
- **API**: RESTful endpoints with comprehensive error handling
- **Monitoring**: Health checks, audit logging, performance metrics

### Frontend (React/TypeScript)
- **UI Framework**: React with TypeScript
- **Styling**: Tailwind CSS with shadcn/ui components
- **State Management**: React Query for server state
- **Routing**: React Router
- **Forms**: React Hook Form with Zod validation

### Database Schema
- **Users**: Authentication and profile management
- **Medical Records**: Test results and health data
- **Appointments**: Healthcare appointment tracking
- **Prescriptions**: Medication management
- **Emergency Contacts**: Critical contact information
- **Chat History**: AI conversation logs
- **Audit Logs**: Security and compliance tracking

## 🛠️ Installation

### Prerequisites
- Node.js 18+
- npm or yarn
- Supabase account
- OpenRouter API key

### Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd NINA
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Database Setup**
   - Create a Supabase project
   - Run the SQL setup script in `database-setup.sql`
   - Update Supabase credentials in `.env`

5. **Start Development Server**
   ```bash
   npm run dev
   ```

## 🔧 Configuration

### Environment Variables

See `.env.example` for all configuration options. Key settings include:

- **Database**: Supabase URL and keys
- **AI Service**: OpenRouter API configuration
- **Security**: JWT secrets, encryption keys
- **Rate Limiting**: Request limits and windows
- **HIPAA**: Compliance settings

### Database Setup

Run the provided SQL script in your Supabase SQL editor:

```sql
-- Execute database-setup.sql in Supabase
```

## 🚀 Deployment

### Vercel Deployment

NINA is configured for seamless deployment on Vercel with both frontend and backend support.

#### Prerequisites
- Vercel account
- Supabase project
- OpenRouter API key

#### Deployment Steps

1. **Connect Repository**
   ```bash
   # Install Vercel CLI
   npm i -g vercel

   # Login to Vercel
   vercel login

   # Deploy
   vercel
   ```

2. **Environment Variables**
   Set the following environment variables in your Vercel project settings:
   - `NODE_ENV=production`
   - `SUPABASE_URL=your-supabase-url`
   - `SUPABASE_ANON_KEY=your-anon-key`
   - `SUPABASE_SERVICE_ROLE_KEY=your-service-role-key`
   - `OPENROUTER_API_KEY=your-openrouter-key`
   - `JWT_SECRET=your-jwt-secret`
   - `ENCRYPTION_KEY=your-encryption-key`
   - `ALLOWED_ORIGINS=https://your-app.vercel.app`

3. **Build Configuration**
   Vercel automatically detects the `vercel.json` configuration and builds both client and server components.

#### Alternative: Manual Build

```bash
npm run build
npm run build:server
npm start
```

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3001
CMD ["npm", "start"]
```

### Environment Setup

For production deployment:

1. Set `NODE_ENV=production`
2. Configure production database
3. Set up proper CORS origins
4. Enable HTTPS
5. Configure monitoring and logging

## 🔒 Security

### HIPAA Compliance Features

- **Data Encryption**: All sensitive data encrypted at rest and in transit
- **Access Controls**: Role-based permissions with audit trails
- **Data Minimization**: Only collect necessary healthcare information
- **Secure Communication**: HTTPS required, secure headers
- **Audit Logging**: All data access logged for compliance

### Security Best Practices

- **Input Validation**: Comprehensive validation on all inputs
- **Rate Limiting**: Protection against brute force and DoS
- **CORS Configuration**: Restricted cross-origin requests
- **Helmet Security Headers**: Security headers for all responses
- **Dependency Scanning**: Regular security updates

## 📊 Monitoring

### Health Checks

- **System Health**: `/api/health` - Overall system status
- **Detailed Health**: `/api/health/detailed` - Comprehensive metrics
- **Database Connectivity**: Automatic database health monitoring
- **AI Service Status**: External API availability checks

### Logging

- **Application Logs**: Structured logging with Winston
- **Audit Logs**: HIPAA-compliant activity tracking
- **Error Tracking**: Comprehensive error logging and alerting
- **Performance Monitoring**: Response times and throughput metrics

## 🧪 Testing

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run E2E tests
npm run test:e2e
```

## 📚 API Documentation

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `POST /auth/logout` - User logout

### Healthcare Endpoints
- `GET /api/medical-records` - List medical records
- `POST /api/medical-records` - Create medical record
- `GET /api/appointments` - List appointments
- `POST /api/appointments` - Schedule appointment
- `GET /api/prescriptions` - List prescriptions
- `POST /api/prescriptions` - Add prescription

### System Endpoints
- `GET /api/health` - System health check
- `GET /api/audit/user` - User audit logs

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This application is designed to assist with healthcare management but is not a substitute for professional medical advice. Always consult qualified healthcare providers for medical decisions.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting guide

---

Built with ❤️ for better healthcare management
