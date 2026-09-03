-- Add reversible product archival.
ALTER TABLE products
    ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

-- Product types are free text in the API. Remove the old legacy restriction.
ALTER TABLE products
    DROP CONSTRAINT IF EXISTS products_type_check;
