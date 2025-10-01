# KYC Age Verification App

A comprehensive Know Your Customer (KYC) application designed to verify users are 21 years or older. This full-stack application provides secure document upload, age verification, and compliance tracking.

## 🚀 Features

- **Age Verification**: Automatically verifies users are 21+ based on date of birth
- **Document Upload**: Secure upload for ID documents (front/back) and selfie photos
- **Multiple ID Types**: Support for passport, driver's license, and national ID
- **Real-time Validation**: Form validation with detailed error messages
- **Verification Dashboard**: Admin interface to view all verification requests
- **Responsive Design**: Modern, mobile-friendly UI built with Tailwind CSS
- **Security Features**: Rate limiting, file type validation, and secure file storage
- **RESTful API**: Clean API endpoints for integration with other systems

## 🏗️ Architecture

### Backend (Node.js + Express)
- **Framework**: Express.js with TypeScript support
- **File Upload**: Multer for handling multipart form data
- **Validation**: Joi for request validation
- **Security**: Helmet, CORS, rate limiting
- **Storage**: Local file system (easily extendable to cloud storage)

### Frontend (React + TypeScript)
- **Framework**: React 18 with TypeScript
- **Routing**: React Router for navigation
- **Forms**: React Hook Form with Yup validation
- **Styling**: Tailwind CSS with custom components
- **Icons**: Lucide React for consistent iconography
- **HTTP Client**: Axios for API communication

## 📋 Prerequisites

- Node.js (v16 or higher)
- npm or yarn
- Modern web browser

## 🛠️ Installation

### Quick Start

1. **Clone and setup the project**:
   ```bash
   cd /workspace/kyc-app
   npm run install-all
   ```

2. **Start the development servers**:
   ```bash
   npm run dev
   ```

   This will start both the backend server (port 5000) and frontend development server (port 3000).

### Manual Setup

1. **Install root dependencies**:
   ```bash
   npm install
   ```

2. **Install server dependencies**:
   ```bash
   cd server
   npm install
   cd ..
   ```

3. **Install client dependencies**:
   ```bash
   cd client
   npm install
   cd ..
   ```

4. **Start the backend server**:
   ```bash
   cd server
   npm start
   ```

5. **Start the frontend (in a new terminal)**:
   ```bash
   cd client
   npm start
   ```

## 🌐 Usage

### For End Users

1. **Access the Application**: Open http://localhost:3000 in your browser
2. **Start Verification**: Click "Start Verification" on the homepage
3. **Fill Personal Information**: 
   - First and last name
   - Date of birth
   - Email and phone number
   - Complete address
4. **Document Information**:
   - Select document type (Passport, Driver's License, or National ID)
   - Enter document number
5. **Upload Documents**:
   - Upload front of ID document (required)
   - Upload back of ID document (optional, for driver's license)
   - Upload selfie photo (required)
6. **Submit and Review**: Submit form and receive instant verification results

### For Administrators

1. **Access Dashboard**: Navigate to http://localhost:3000/dashboard
2. **View Statistics**: See total, approved, and rejected verifications
3. **Search and Filter**: Use search and status filters to find specific records
4. **Review Details**: View detailed information for each verification request

## 📡 API Endpoints

### Health Check
```
GET /api/health
```
Returns server status and health information.

### Submit KYC Verification
```
POST /api/verify-kyc
Content-Type: multipart/form-data
```

**Required Fields**:
- `firstName`, `lastName`, `dateOfBirth`, `email`, `phone`
- `address[street]`, `address[city]`, `address[state]`, `address[zipCode]`, `address[country]`
- `documentType`, `documentNumber`
- `documentFront` (file), `selfie` (file)
- `documentBack` (file, optional)

**Response**:
```json
{
  "success": true,
  "verificationId": "uuid",
  "status": "approved|rejected",
  "isOver21": true,
  "age": 25,
  "message": "Age verification passed",
  "data": {
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "verificationDate": "2023-10-01T12:00:00Z"
  }
}
```

### Get Verification Record
```
GET /api/verification/:id
```
Returns details for a specific verification record.

### Get All Verifications
```
GET /api/verifications
```
Returns all verification records (for admin dashboard).

## 🔒 Security Features

- **File Upload Security**: 
  - File type validation (JPEG, JPG, PNG, PDF only)
  - File size limits (5MB maximum)
  - Unique filename generation to prevent conflicts
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **Input Validation**: Comprehensive validation using Joi schemas
- **CORS Protection**: Configurable cross-origin resource sharing
- **Helmet Security**: Security headers for production deployment

## 📁 Project Structure

```
kyc-app/
├── client/                 # React frontend
│   ├── public/            # Static assets
│   ├── src/
│   │   ├── components/    # React components
│   │   ├── services/      # API service layer
│   │   ├── types/         # TypeScript type definitions
│   │   └── App.tsx        # Main application component
│   └── package.json
├── server/                # Express backend
│   ├── uploads/          # Uploaded files storage
│   ├── index.js          # Main server file
│   └── package.json
├── package.json          # Root package.json
└── README.md
```

## 🎨 UI Components

### KYC Form
- Multi-step form with validation
- File upload with drag-and-drop
- Real-time validation feedback
- Progress indicators

### Verification Dashboard
- Statistics overview
- Search and filtering
- Responsive data table
- Status indicators

### Navigation
- Clean, modern navigation bar
- Active route highlighting
- Mobile-responsive design

## 🧪 Validation Rules

### Personal Information
- **Name**: Minimum 2 characters, maximum 50 characters
- **Date of Birth**: Must be a valid date, not in the future
- **Email**: Valid email format required
- **Phone**: International phone number format

### Address
- **Street**: Minimum 5 characters
- **City/State**: Minimum 2 characters
- **ZIP Code**: Minimum 5 characters
- **Country**: Minimum 2 characters

### Documents
- **Document Number**: Format validation based on document type
  - Passport: 6-9 alphanumeric characters
  - Driver's License: 8-15 alphanumeric characters
  - National ID: 8-12 alphanumeric characters

## 🚀 Deployment

### Environment Variables

Create a `.env` file in the server directory:

```env
PORT=5000
CLIENT_URL=http://localhost:3000
NODE_ENV=production
```

Create a `.env` file in the client directory:

```env
REACT_APP_API_URL=http://localhost:5000/api
```

### Production Build

1. **Build the client**:
   ```bash
   cd client
   npm run build
   ```

2. **Start the server**:
   ```bash
   cd server
   npm start
   ```

## 🔧 Customization

### Adding New Document Types
1. Update the `documentType` enum in `types/index.ts`
2. Add validation pattern in `server/index.js`
3. Update the form options in `KYCForm.tsx`

### Integrating with Cloud Storage
Replace the local file storage in `server/index.js` with your preferred cloud storage solution (AWS S3, Google Cloud Storage, etc.).

### Database Integration
Currently using in-memory storage. For production, integrate with your preferred database:
- PostgreSQL with Prisma
- MongoDB with Mongoose
- MySQL with Sequelize

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**: Change ports in package.json scripts
2. **File Upload Fails**: Check file size (max 5MB) and type (JPEG, JPG, PNG, PDF)
3. **CORS Errors**: Ensure CLIENT_URL environment variable is set correctly
4. **Validation Errors**: Check that all required fields are filled correctly

### Development Tips

- Use browser developer tools to inspect network requests
- Check server logs for detailed error messages
- Ensure both frontend and backend servers are running
- Verify file permissions for the uploads directory

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

---

**Note**: This application is designed for demonstration purposes. For production use, ensure proper security measures, database integration, and compliance with local regulations regarding data handling and privacy.