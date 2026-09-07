-- Add display_name column to vapt_imports for clean report titles shown to clients.
-- The raw filename is kept in file_name for internal reference.
ALTER TABLE vapt_imports ADD COLUMN display_name VARCHAR(255) NULL;
