const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const Joi = require('joi');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only JPEG, JPG, PNG, and PDF files are allowed'));
    }
  }
});

// Validation schemas
const kycSchema = Joi.object({
  firstName: Joi.string().min(2).max(50).required(),
  lastName: Joi.string().min(2).max(50).required(),
  dateOfBirth: Joi.date().max('now').required(),
  email: Joi.string().email().required(),
  phone: Joi.string().pattern(/^[+]?[1-9][\d]{0,15}$/).required(),
  address: Joi.object({
    street: Joi.string().min(5).max(100).required(),
    city: Joi.string().min(2).max(50).required(),
    state: Joi.string().min(2).max(50).required(),
    zipCode: Joi.string().min(5).max(10).required(),
    country: Joi.string().min(2).max(50).required()
  }).required(),
  documentType: Joi.string().valid('passport', 'driverLicense', 'nationalId').required(),
  documentNumber: Joi.string().min(5).max(20).required()
});

// In-memory storage for demo (use database in production)
const verificationRecords = new Map();

// Helper function to calculate age
const calculateAge = (dateOfBirth) => {
  return moment().diff(moment(dateOfBirth), 'years');
};

// Helper function to validate document format
const validateDocumentNumber = (documentType, documentNumber) => {
  const patterns = {
    passport: /^[A-Z0-9]{6,9}$/,
    driverLicense: /^[A-Z0-9]{8,15}$/,
    nationalId: /^[A-Z0-9]{8,12}$/
  };
  
  return patterns[documentType] ? patterns[documentType].test(documentNumber.toUpperCase()) : false;
};

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'KYC API is running' });
});

app.post('/api/verify-kyc', upload.fields([
  { name: 'documentFront', maxCount: 1 },
  { name: 'documentBack', maxCount: 1 },
  { name: 'selfie', maxCount: 1 }
]), async (req, res) => {
  try {
    // Validate request body
    const { error, value } = kycSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation error',
        errors: error.details.map(detail => detail.message)
      });
    }

    const { firstName, lastName, dateOfBirth, email, phone, address, documentType, documentNumber } = value;

    // Check if required files are uploaded
    if (!req.files || !req.files.documentFront || !req.files.selfie) {
      return res.status(400).json({
        success: false,
        message: 'Required documents missing. Please upload document front and selfie.'
      });
    }

    // Calculate age
    const age = calculateAge(dateOfBirth);
    const isOver21 = age >= 21;

    // Validate document number format
    const isValidDocumentNumber = validateDocumentNumber(documentType, documentNumber);
    if (!isValidDocumentNumber) {
      return res.status(400).json({
        success: false,
        message: 'Invalid document number format for the selected document type.'
      });
    }

    // Check if user already exists
    const existingRecord = Array.from(verificationRecords.values()).find(
      record => record.email === email || record.documentNumber === documentNumber.toUpperCase()
    );

    if (existingRecord) {
      return res.status(409).json({
        success: false,
        message: 'A verification record already exists for this email or document number.'
      });
    }

    // Create verification record
    const verificationId = uuidv4();
    const verificationRecord = {
      id: verificationId,
      firstName,
      lastName,
      dateOfBirth,
      age,
      email,
      phone,
      address,
      documentType,
      documentNumber: documentNumber.toUpperCase(),
      documents: {
        front: req.files.documentFront[0].filename,
        back: req.files.documentBack ? req.files.documentBack[0].filename : null,
        selfie: req.files.selfie[0].filename
      },
      verificationStatus: isOver21 ? 'approved' : 'rejected',
      verificationReason: isOver21 ? 'Age verification passed' : 'User is under 21 years old',
      createdAt: new Date().toISOString(),
      isOver21
    };

    verificationRecords.set(verificationId, verificationRecord);

    // Return response
    res.json({
      success: true,
      verificationId,
      status: verificationRecord.verificationStatus,
      isOver21,
      age,
      message: verificationRecord.verificationReason,
      data: {
        firstName,
        lastName,
        email,
        verificationDate: verificationRecord.createdAt
      }
    });

  } catch (error) {
    console.error('KYC verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during verification process.'
    });
  }
});

app.get('/api/verification/:id', (req, res) => {
  const { id } = req.params;
  const record = verificationRecords.get(id);

  if (!record) {
    return res.status(404).json({
      success: false,
      message: 'Verification record not found.'
    });
  }

  // Return sanitized record (without sensitive data)
  res.json({
    success: true,
    data: {
      id: record.id,
      firstName: record.firstName,
      lastName: record.lastName,
      email: record.email,
      age: record.age,
      verificationStatus: record.verificationStatus,
      verificationReason: record.verificationReason,
      isOver21: record.isOver21,
      createdAt: record.createdAt
    }
  });
});

app.get('/api/verifications', (req, res) => {
  const records = Array.from(verificationRecords.values()).map(record => ({
    id: record.id,
    firstName: record.firstName,
    lastName: record.lastName,
    email: record.email,
    age: record.age,
    verificationStatus: record.verificationStatus,
    isOver21: record.isOver21,
    createdAt: record.createdAt
  }));

  res.json({
    success: true,
    count: records.length,
    data: records
  });
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 5MB.'
      });
    }
  }
  
  res.status(500).json({
    success: false,
    message: error.message || 'Something went wrong!'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

app.listen(PORT, () => {
  console.log(`KYC Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app;