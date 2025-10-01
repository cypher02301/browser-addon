import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { Upload, User, Mail, Phone, MapPin, FileText, Camera, CheckCircle, XCircle, AlertCircle } from 'lucide-react';
import { KYCFormData, VerificationResponse } from '../types';
import { submitKYCVerification } from '../services/api';

const schema = yup.object({
  firstName: yup.string().required('First name is required').min(2, 'Minimum 2 characters'),
  lastName: yup.string().required('Last name is required').min(2, 'Minimum 2 characters'),
  dateOfBirth: yup.string().required('Date of birth is required'),
  email: yup.string().email('Invalid email format').required('Email is required'),
  phone: yup.string().required('Phone number is required').matches(/^[+]?[1-9][\d]{0,15}$/, 'Invalid phone number'),
  address: yup.object({
    street: yup.string().required('Street address is required').min(5, 'Minimum 5 characters'),
    city: yup.string().required('City is required').min(2, 'Minimum 2 characters'),
    state: yup.string().required('State is required').min(2, 'Minimum 2 characters'),
    zipCode: yup.string().required('ZIP code is required').min(5, 'Minimum 5 characters'),
    country: yup.string().required('Country is required').min(2, 'Minimum 2 characters'),
  }),
  documentType: yup.string().oneOf(['passport', 'driverLicense', 'nationalId']).required('Document type is required'),
  documentNumber: yup.string().required('Document number is required').min(5, 'Minimum 5 characters'),
});

const KYCForm: React.FC = () => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [verificationResult, setVerificationResult] = useState<VerificationResponse | null>(null);
  const [documentFront, setDocumentFront] = useState<File | null>(null);
  const [documentBack, setDocumentBack] = useState<File | null>(null);
  const [selfie, setSelfie] = useState<File | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<Omit<KYCFormData, 'documentFront' | 'documentBack' | 'selfie'>>({
    resolver: yupResolver(schema),
  });

  const handleFileChange = (type: 'documentFront' | 'documentBack' | 'selfie') => (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0] || null;
    switch (type) {
      case 'documentFront':
        setDocumentFront(file);
        break;
      case 'documentBack':
        setDocumentBack(file);
        break;
      case 'selfie':
        setSelfie(file);
        break;
    }
  };

  const onSubmit = async (data: Omit<KYCFormData, 'documentFront' | 'documentBack' | 'selfie'>) => {
    if (!documentFront || !selfie) {
      alert('Please upload required documents (ID front and selfie)');
      return;
    }

    setIsSubmitting(true);
    try {
      const formData: KYCFormData = {
        ...data,
        documentFront,
        documentBack,
        selfie,
      };

      const result = await submitKYCVerification(formData);
      setVerificationResult(result);
    } catch (error: any) {
      console.error('Verification failed:', error);
      setVerificationResult({
        success: false,
        message: error.response?.data?.message || 'Verification failed. Please try again.',
        errors: error.response?.data?.errors || [],
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  const resetForm = () => {
    reset();
    setDocumentFront(null);
    setDocumentBack(null);
    setSelfie(null);
    setVerificationResult(null);
  };

  if (verificationResult) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            {verificationResult.success ? (
              <CheckCircle className="mx-auto h-16 w-16 text-green-500" />
            ) : (
              <XCircle className="mx-auto h-16 w-16 text-red-500" />
            )}
            <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
              Verification {verificationResult.success ? 'Successful' : 'Failed'}
            </h2>
            <p className="mt-2 text-sm text-gray-600">
              {verificationResult.message}
            </p>
          </div>

          {verificationResult.success && verificationResult.data && (
            <div className="bg-white shadow rounded-lg p-6">
              <h3 className="text-lg font-medium text-gray-900 mb-4">Verification Details</h3>
              <div className="space-y-2">
                <p><span className="font-medium">Name:</span> {verificationResult.data.firstName} {verificationResult.data.lastName}</p>
                <p><span className="font-medium">Email:</span> {verificationResult.data.email}</p>
                <p><span className="font-medium">Age:</span> {verificationResult.age} years</p>
                <p><span className="font-medium">Status:</span> 
                  <span className={`ml-2 px-2 py-1 rounded text-sm ${
                    verificationResult.isOver21 ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {verificationResult.isOver21 ? 'Approved (21+)' : 'Rejected (Under 21)'}
                  </span>
                </p>
                <p><span className="font-medium">Verification ID:</span> {verificationResult.verificationId}</p>
              </div>
            </div>
          )}

          {verificationResult.errors && verificationResult.errors.length > 0 && (
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <div className="flex">
                <AlertCircle className="h-5 w-5 text-red-400" />
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Validation Errors</h3>
                  <div className="mt-2 text-sm text-red-700">
                    <ul className="list-disc pl-5 space-y-1">
                      {verificationResult.errors.map((error, index) => (
                        <li key={index}>{error}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          )}

          <button
            onClick={resetForm}
            className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            Submit Another Verification
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-extrabold text-gray-900">Age Verification (21+)</h1>
          <p className="mt-2 text-sm text-gray-600">
            Please provide your information and documents to verify you are 21 years or older
          </p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6 bg-white shadow rounded-lg p-6">
          {/* Personal Information */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <User className="h-5 w-5 mr-2" />
              Personal Information
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="firstName" className="block text-sm font-medium text-gray-700">
                  First Name *
                </label>
                <input
                  {...register('firstName')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.firstName && <p className="mt-1 text-sm text-red-600">{errors.firstName.message}</p>}
              </div>

              <div>
                <label htmlFor="lastName" className="block text-sm font-medium text-gray-700">
                  Last Name *
                </label>
                <input
                  {...register('lastName')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.lastName && <p className="mt-1 text-sm text-red-600">{errors.lastName.message}</p>}
              </div>

              <div>
                <label htmlFor="dateOfBirth" className="block text-sm font-medium text-gray-700">
                  Date of Birth *
                </label>
                <input
                  {...register('dateOfBirth')}
                  type="date"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.dateOfBirth && <p className="mt-1 text-sm text-red-600">{errors.dateOfBirth.message}</p>}
              </div>

              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                  <Mail className="inline h-4 w-4 mr-1" />
                  Email *
                </label>
                <input
                  {...register('email')}
                  type="email"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.email && <p className="mt-1 text-sm text-red-600">{errors.email.message}</p>}
              </div>

              <div className="sm:col-span-2">
                <label htmlFor="phone" className="block text-sm font-medium text-gray-700">
                  <Phone className="inline h-4 w-4 mr-1" />
                  Phone Number *
                </label>
                <input
                  {...register('phone')}
                  type="tel"
                  placeholder="+1234567890"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.phone && <p className="mt-1 text-sm text-red-600">{errors.phone.message}</p>}
              </div>
            </div>
          </div>

          {/* Address Information */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <MapPin className="h-5 w-5 mr-2" />
              Address Information
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div className="sm:col-span-2">
                <label htmlFor="address.street" className="block text-sm font-medium text-gray-700">
                  Street Address *
                </label>
                <input
                  {...register('address.street')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.address?.street && <p className="mt-1 text-sm text-red-600">{errors.address.street.message}</p>}
              </div>

              <div>
                <label htmlFor="address.city" className="block text-sm font-medium text-gray-700">
                  City *
                </label>
                <input
                  {...register('address.city')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.address?.city && <p className="mt-1 text-sm text-red-600">{errors.address.city.message}</p>}
              </div>

              <div>
                <label htmlFor="address.state" className="block text-sm font-medium text-gray-700">
                  State *
                </label>
                <input
                  {...register('address.state')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.address?.state && <p className="mt-1 text-sm text-red-600">{errors.address.state.message}</p>}
              </div>

              <div>
                <label htmlFor="address.zipCode" className="block text-sm font-medium text-gray-700">
                  ZIP Code *
                </label>
                <input
                  {...register('address.zipCode')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.address?.zipCode && <p className="mt-1 text-sm text-red-600">{errors.address.zipCode.message}</p>}
              </div>

              <div>
                <label htmlFor="address.country" className="block text-sm font-medium text-gray-700">
                  Country *
                </label>
                <input
                  {...register('address.country')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.address?.country && <p className="mt-1 text-sm text-red-600">{errors.address.country.message}</p>}
              </div>
            </div>
          </div>

          {/* Document Information */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              Document Information
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="documentType" className="block text-sm font-medium text-gray-700">
                  Document Type *
                </label>
                <select
                  {...register('documentType')}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                >
                  <option value="">Select document type</option>
                  <option value="passport">Passport</option>
                  <option value="driverLicense">Driver's License</option>
                  <option value="nationalId">National ID</option>
                </select>
                {errors.documentType && <p className="mt-1 text-sm text-red-600">{errors.documentType.message}</p>}
              </div>

              <div>
                <label htmlFor="documentNumber" className="block text-sm font-medium text-gray-700">
                  Document Number *
                </label>
                <input
                  {...register('documentNumber')}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.documentNumber && <p className="mt-1 text-sm text-red-600">{errors.documentNumber.message}</p>}
              </div>
            </div>
          </div>

          {/* File Uploads */}
          <div>
            <h3 className="text-lg font-medium text-gray-900 mb-4 flex items-center">
              <Upload className="h-5 w-5 mr-2" />
              Document Upload
            </h3>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Document Front * (Max 5MB)
                </label>
                <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  <div className="space-y-1 text-center">
                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                    <div className="flex text-sm text-gray-600">
                      <label className="relative cursor-pointer bg-white rounded-md font-medium text-primary-600 hover:text-primary-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-primary-500">
                        <span>Upload front</span>
                        <input
                          type="file"
                          accept="image/*,.pdf"
                          onChange={handleFileChange('documentFront')}
                          className="sr-only"
                        />
                      </label>
                    </div>
                    <p className="text-xs text-gray-500">PNG, JPG, PDF up to 5MB</p>
                    {documentFront && <p className="text-sm text-green-600">✓ {documentFront.name}</p>}
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Document Back (Optional)
                </label>
                <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  <div className="space-y-1 text-center">
                    <Upload className="mx-auto h-12 w-12 text-gray-400" />
                    <div className="flex text-sm text-gray-600">
                      <label className="relative cursor-pointer bg-white rounded-md font-medium text-primary-600 hover:text-primary-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-primary-500">
                        <span>Upload back</span>
                        <input
                          type="file"
                          accept="image/*,.pdf"
                          onChange={handleFileChange('documentBack')}
                          className="sr-only"
                        />
                      </label>
                    </div>
                    <p className="text-xs text-gray-500">PNG, JPG, PDF up to 5MB</p>
                    {documentBack && <p className="text-sm text-green-600">✓ {documentBack.name}</p>}
                  </div>
                </div>
              </div>

              <div className="sm:col-span-2">
                <label className="block text-sm font-medium text-gray-700">
                  <Camera className="inline h-4 w-4 mr-1" />
                  Selfie Photo * (Max 5MB)
                </label>
                <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md">
                  <div className="space-y-1 text-center">
                    <Camera className="mx-auto h-12 w-12 text-gray-400" />
                    <div className="flex text-sm text-gray-600">
                      <label className="relative cursor-pointer bg-white rounded-md font-medium text-primary-600 hover:text-primary-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-offset-2 focus-within:ring-primary-500">
                        <span>Upload selfie</span>
                        <input
                          type="file"
                          accept="image/*"
                          onChange={handleFileChange('selfie')}
                          className="sr-only"
                        />
                      </label>
                    </div>
                    <p className="text-xs text-gray-500">PNG, JPG up to 5MB</p>
                    {selfie && <p className="text-sm text-green-600">✓ {selfie.name}</p>}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-6">
            <button
              type="submit"
              disabled={isSubmitting}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting ? (
                <>
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Verifying...
                </>
              ) : (
                'Submit for Verification'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default KYCForm;