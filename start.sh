#!/bin/bash
# BountyBot Development Startup Script

echo "🚀 Starting BountyBot Development Environment..."
echo ""

# Start PostgreSQL and Redis in Docker
echo "📦 Starting PostgreSQL and Redis..."
docker compose up -d db redis

# Wait for databases to be ready
echo "⏳ Waiting for databases to start..."
sleep 3

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Run: python3 -m venv venv"
    exit 1
fi

# Activate virtual environment and start Django
echo "🐍 Starting Django development server..."
echo ""
source venv/bin/activate
python manage.py runserver