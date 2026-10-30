ALTER TABLE cloud_security_assessments
ADD COLUMN IF NOT EXISTS client_name VARCHAR(255) NULL;
