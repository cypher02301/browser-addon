export interface Address {
  street: string;
  city: string;
  state: string;
  zipCode: string;
  country: string;
}

export interface KYCFormData {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  email: string;
  phone: string;
  address: Address;
  documentType: 'passport' | 'driverLicense' | 'nationalId';
  documentNumber: string;
  documentFront: File | null;
  documentBack: File | null;
  selfie: File | null;
}

export interface VerificationResponse {
  success: boolean;
  verificationId?: string;
  status?: 'approved' | 'rejected';
  isOver21?: boolean;
  age?: number;
  message?: string;
  data?: {
    firstName: string;
    lastName: string;
    email: string;
    verificationDate: string;
  };
  errors?: string[];
}

export interface VerificationRecord {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  age: number;
  verificationStatus: 'approved' | 'rejected';
  verificationReason: string;
  isOver21: boolean;
  createdAt: string;
}