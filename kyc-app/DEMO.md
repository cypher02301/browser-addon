# KYC Age Verification App - Demo Guide

## 🎯 Quick Demo

This KYC application verifies users are 21+ years old through document upload and validation.

### 🚀 Quick Start

1. **Start the application**:
   ```bash
   cd /workspace/kyc-app
   ./start.sh
   ```
   Or manually:
   ```bash
   # Terminal 1 - Backend
   cd server && node index.js
   
   # Terminal 2 - Frontend  
   cd client && npm start
   ```

2. **Access the application**: Open http://localhost:3000

### 📋 Demo Scenarios

#### Scenario 1: Successful Verification (21+ User)
1. Navigate to "Start Verification"
2. Fill in personal information:
   - **Name**: John Doe
   - **Date of Birth**: 01/01/1990 (33+ years old)
   - **Email**: john.doe@example.com
   - **Phone**: +1234567890
   - **Address**: Complete address information
3. Document information:
   - **Type**: Driver's License
   - **Number**: DL123456789
4. Upload files:
   - **Document Front**: Any image file (JPG/PNG)
   - **Selfie**: Any image file (JPG/PNG)
5. Submit and see **APPROVED** result

#### Scenario 2: Rejected Verification (Under 21)
1. Use the same process but with:
   - **Date of Birth**: 01/01/2010 (13 years old)
2. Submit and see **REJECTED** result

#### Scenario 3: Validation Errors
1. Try submitting with missing fields
2. Try uploading invalid file types
3. Try entering invalid phone numbers or email formats

### 🎛️ Admin Dashboard Features

1. Navigate to "Dashboard" in the navigation
2. View verification statistics:
   - Total verifications
   - Approved count (21+)
   - Rejected count (Under 21)
3. Search and filter verifications:
   - Search by name, email, or verification ID
   - Filter by approval status
4. View detailed verification records

### 🔍 API Testing

Test the API directly using curl:

```bash
# Health check
curl http://localhost:5000/api/health

# Get all verifications
curl http://localhost:5000/api/verifications

# Get specific verification (replace ID)
curl http://localhost:5000/api/verification/[VERIFICATION_ID]
```

### 📱 Mobile Testing

The application is fully responsive. Test on different screen sizes:
- Desktop (1200px+)
- Tablet (768px - 1199px)
- Mobile (320px - 767px)

### 🔒 Security Features Demo

1. **Rate Limiting**: Try making 100+ requests quickly to see rate limiting
2. **File Validation**: Try uploading non-image files to see rejection
3. **Input Validation**: Submit forms with invalid data to see validation errors
4. **File Size Limits**: Try uploading files larger than 5MB

### 🎨 UI/UX Features

1. **Form Validation**: Real-time validation feedback
2. **File Upload**: Drag-and-drop file upload areas
3. **Loading States**: Spinner during form submission
4. **Success/Error States**: Clear feedback on verification results
5. **Responsive Design**: Works on all device sizes
6. **Accessibility**: Proper labels, focus states, and keyboard navigation

### 📊 Sample Test Data

Use these sample data sets for testing:

**Adult User (Will be Approved)**:
- Name: Jane Smith
- DOB: 03/15/1985
- Email: jane.smith@example.com
- Phone: +1987654321
- Document: Passport P123456789

**Minor User (Will be Rejected)**:
- Name: Alex Johnson
- DOB: 12/25/2008
- Email: alex.johnson@example.com
- Phone: +1555123456
- Document: National ID N987654321

### 🔧 Development Features

1. **Hot Reload**: Frontend updates automatically during development
2. **Error Handling**: Comprehensive error messages and logging
3. **TypeScript**: Full type safety in frontend
4. **Modern Stack**: Latest React, Express, and styling frameworks

### 🚨 Troubleshooting

**Common Issues**:
1. **Port conflicts**: Change ports in package.json if 3000/5000 are in use
2. **File upload fails**: Check file size (<5MB) and type (JPG/PNG/PDF)
3. **CORS errors**: Ensure both servers are running on correct ports
4. **Build errors**: Run `npm install` in both client and server directories

**Reset Demo Data**:
- Restart the server to clear all verification records
- Data is stored in memory for demo purposes

### 📈 Performance Notes

- File uploads are limited to 5MB for performance
- In-memory storage for demo (use database for production)
- Rate limiting prevents abuse (100 requests per 15 minutes)
- Optimized build reduces bundle size significantly

---

**🎉 Enjoy exploring the KYC Age Verification App!**

For questions or issues, check the main README.md file or create an issue in the repository.