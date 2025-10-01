import axios from 'axios';
import { KYCFormData, VerificationResponse, VerificationRecord } from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

export const submitKYCVerification = async (formData: KYCFormData): Promise<VerificationResponse> => {
  const submitData = new FormData();
  
  // Add text fields
  submitData.append('firstName', formData.firstName);
  submitData.append('lastName', formData.lastName);
  submitData.append('dateOfBirth', formData.dateOfBirth);
  submitData.append('email', formData.email);
  submitData.append('phone', formData.phone);
  submitData.append('documentType', formData.documentType);
  submitData.append('documentNumber', formData.documentNumber);
  
  // Add address fields
  submitData.append('address[street]', formData.address.street);
  submitData.append('address[city]', formData.address.city);
  submitData.append('address[state]', formData.address.state);
  submitData.append('address[zipCode]', formData.address.zipCode);
  submitData.append('address[country]', formData.address.country);
  
  // Add files
  if (formData.documentFront) {
    submitData.append('documentFront', formData.documentFront);
  }
  if (formData.documentBack) {
    submitData.append('documentBack', formData.documentBack);
  }
  if (formData.selfie) {
    submitData.append('selfie', formData.selfie);
  }

  const response = await api.post<VerificationResponse>('/verify-kyc', submitData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });

  return response.data;
};

export const getVerificationRecord = async (id: string): Promise<VerificationRecord> => {
  const response = await api.get<{ success: boolean; data: VerificationRecord }>(`/verification/${id}`);
  return response.data.data;
};

export const getAllVerifications = async (): Promise<VerificationRecord[]> => {
  const response = await api.get<{ success: boolean; data: VerificationRecord[] }>('/verifications');
  return response.data.data;
};

export const checkHealth = async (): Promise<{ status: string; message: string }> => {
  const response = await api.get<{ status: string; message: string }>('/health');
  return response.data;
};