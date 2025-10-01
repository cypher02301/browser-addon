#!/bin/bash

echo "🚀 Starting KYC Age Verification App..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "📦 Installing dependencies..."

# Install root dependencies
npm install

# Install server dependencies
cd server
npm install
cd ..

# Install client dependencies
cd client
npm install
cd ..

echo "✅ Dependencies installed successfully!"

echo "🔧 Starting servers..."

# Start the backend server in the background
cd server
node index.js &
SERVER_PID=$!
cd ..

# Wait a moment for the server to start
sleep 3

# Check if server is running
if curl -s http://localhost:5000/api/health > /dev/null; then
    echo "✅ Backend server is running on http://localhost:5000"
else
    echo "❌ Failed to start backend server"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Start the frontend development server
cd client
echo "🌐 Starting frontend development server..."
echo "📱 Frontend will be available at http://localhost:3000"
echo "🔧 Backend API is running at http://localhost:5000"
echo ""
echo "Press Ctrl+C to stop both servers"

# This will start the React development server
npm start

# Clean up: kill the backend server when the frontend stops
kill $SERVER_PID 2>/dev/null