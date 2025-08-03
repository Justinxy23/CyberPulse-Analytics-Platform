#!/bin/bash
# CyberPulse Analytics Platform - Docker Entrypoint Script
# Author: Justin Christopher Weaver

set -e

echo "🚀 Starting CyberPulse Analytics Platform..."

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL..."
while ! nc -z ${DB_HOST:-postgres} ${DB_PORT:-5432}; do
    sleep 1
done
echo "✅ PostgreSQL is ready!"

# Wait for Redis to be ready
echo "⏳ Waiting for Redis..."
while ! nc -z ${REDIS_HOST:-redis} ${REDIS_PORT:-6379}; do
    sleep 1
done
echo "✅ Redis is ready!"

# Run database migrations
echo "🔄 Running database migrations..."
cd /app
alembic upgrade head || {
    echo "❌ Failed to run migrations. Initializing database..."
    # If migrations fail, it might be the first run
    python -c "
from src.api_server import engine, Base
Base.metadata.create_all(bind=engine)
print('✅ Database initialized!')
"
}

# Create default admin user if it doesn't exist
echo "👤 Checking for default admin user..."
python -c "
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.api_server import User
import hashlib

db_url = os.getenv('DATABASE_URL')
engine = create_engine(db_url)
Session = sessionmaker(bind=engine)
session = Session()

admin = session.query(User).filter_by(username='admin').first()
if not admin:
    password = os.getenv('ADMIN_PASSWORD', 'CyberPulse2024!')
    admin = User(
        username='admin',
        email='admin@cyberpulse.local',
        full_name='System Administrator',
        role='ADMIN',
        password_hash=hashlib.sha256(password.encode()).hexdigest()
    )
    session.add(admin)
    session.commit()
    print('✅ Default admin user created')
else:
    print('✅ Admin user already exists')
session.close()
"

# Initialize threat intelligence feeds
echo "🔍 Initializing threat intelligence..."
python -c "
from src.threat_detector import ThreatDetectionEngine
import asyncio

async def init_threat_intel():
    engine = ThreatDetectionEngine()
    await engine.update_threat_intelligence()
    print('✅ Threat intelligence updated')

asyncio.run(init_threat_intel())
" || echo "⚠️  Threat intelligence initialization failed (non-critical)"

# Start the application
echo "🚀 Starting API server..."
exec "$@"