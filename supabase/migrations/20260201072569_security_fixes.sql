-- CA Nexus Hub - Critical Security Fixes
-- Fixes: OLD.role issue, column-level security, function abuse, audit schema

-- ============================================
-- FIX 1: Remove OLD.role from profiles policy
-- OLD is not available in WITH CHECK - use trigger instead
-- ============================================

DROP POLICY IF EXISTS "Users can update own profile data" ON profiles;
DROP POLICY IF EXISTS "Admins can update any profile" ON profiles;

CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  TO authenticated
  USING (id::text = auth.uid()::text)
  WITH CHECK (id::text = auth.uid()::text);

-- Create a trigger function to prevent role changes
CREATE OR REPLACE FUNCTION prevent_role_change()
RETURNS TRIGGER AS $$
BEGIN
  -- Only allow role change if user is admin
  IF NEW.role <> OLD.role THEN
    IF NOT EXISTS (
      SELECT 1 FROM profiles 
      WHERE id = auth.uid() AND role = 'admin'
    ) THEN
      RAISE EXCEPTION 'Only admins can change roles';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger
DROP TRIGGER IF EXISTS prevent_role_change ON profiles;
CREATE TRIGGER prevent_role_change
  BEFORE UPDATE ON profiles
  FOR EACH ROW
  EXECUTE FUNCTION prevent_role_change();

-- Users can update their own profile (except role - handled by trigger)
CREATE POLICY "Users can update own profile"
  ON profiles FOR UPDATE
  TO authenticated
  USING (id::text = auth.uid()::text)
  WITH CHECK (id::text = auth.uid()::text);

-- ============================================
-- FIX 2: Column-Level Security via Secure Views
-- ============================================

-- Create view for marketplace (no contact info)
CREATE OR REPLACE VIEW marketplace_leads AS
SELECT 
  id, 
  title, 
  description, 
  category, 
  company_name, 
  budget, 
  status, 
  created_at,
  NULL as phone,
  NULL as email
FROM leads
WHERE status = 'available' OR status IS NULL;

-- Create view for purchased leads (with contact)
CREATE OR REPLACE VIEW purchased_leads_with_contact AS
SELECT 
  pl.id,
  pl.user_id,
  pl.lead_id,
  pl.payment_status,
  pl.paid_at,
  l.title,
  l.description,
  l.category,
  l.company_name,
  l.budget,
  l.phone,
  l.email,
  l.created_at
FROM purchased_leads pl
JOIN leads l ON l.id = pl.lead_id
WHERE pl.payment_status = 'completed';

-- Grant access to views
GRANT SELECT ON marketplace_leads TO anon, authenticated;
GRANT SELECT ON purchased_leads_with_contact TO authenticated;

-- ============================================
-- FIX 3: Secure get_lead_with_contact function
-- Uses auth.uid() - caller cannot impersonate
-- ============================================

DROP FUNCTION IF EXISTS has_lead_access(UUID, UUID);
DROP FUNCTION IF EXISTS get_lead_with_contact(UUID, UUID);

CREATE OR REPLACE FUNCTION has_lead_access(lead_uuid UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM purchased_leads pl
    WHERE pl.user_id = auth.uid()
      AND pl.lead_id = lead_uuid
      AND pl.payment_status = 'completed'
  ) OR EXISTS (
    SELECT 1 FROM profiles p
    WHERE p.id = auth.uid() AND p.role = 'admin'
  );
END;
$$;

CREATE OR REPLACE FUNCTION get_lead_with_contact(lead_uuid UUID)
RETURNS TABLE (
  id uuid,
  title text,
  description text,
  category text,
  company_name text,
  budget numeric,
  phone text,
  email text,
  status text,
  has_access boolean
) 
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Use auth.uid() - cannot be spoofed by caller
  RETURN QUERY
  SELECT 
    l.id,
    l.title,
    l.description,
    l.category,
    l.company_name,
    l.budget,
    CASE 
      WHEN has_lead_access(lead_uuid) THEN l.phone
      ELSE NULL::text
    END as phone,
    CASE 
      WHEN has_lead_access(lead_uuid) THEN l.email
      ELSE NULL::text
    END as email,
    l.status,
    has_lead_access(lead_uuid) as has_access
  FROM leads l
  WHERE l.id = lead_uuid;
END;
$$;

GRANT EXECUTE ON FUNCTION has_lead_access TO authenticated;
GRANT EXECUTE ON FUNCTION get_lead_with_contact TO authenticated;

-- ============================================
-- FIX 4: Drop unsafe get_lead_with_contact with user param
-- ============================================

-- Already fixed above - function now uses auth.uid() only

-- ============================================
-- FIX 5: Update Edge Functions for audit schema
-- ============================================

-- Note: The audit_logs table uses:
-- - action_type (not action)
-- - metadata (not details)
-- 
-- Edge functions already write correctly to these columns
-- This is just for documentation

-- ============================================
-- FIX 6: Add rate limiting to email/WhatsApp
-- Create rate limit table
-- ============================================

CREATE TABLE IF NOT EXISTS rate_limits (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id),
  action_type text NOT NULL,  -- 'email', 'whatsapp'
  count integer DEFAULT 0,
  window_start timestamptz DEFAULT now(),
  created_at timestamptz DEFAULT now()
);

ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

-- No select for users
CREATE POLICY "Rate limits no access" 
  ON rate_limits FOR SELECT TO authenticated USING (false);

-- Service role only
CREATE POLICY "Service role manages rate limits"
  ON rate_limits FOR ALL TO service_role USING (true);

-- Create rate limit check function
CREATE OR REPLACE FUNCTION check_rate_limit(
  p_action_type TEXT,
  p_max_per_hour INTEGER DEFAULT 10
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  v_user_id UUID;
  v_current_count INTEGER;
  v_window_start TIMESTAMPTZ;
BEGIN
  v_user_id := auth.uid();
  
  -- Get or create rate limit record
  SELECT count, window_start INTO v_current_count, v_window_start
  FROM rate_limits
  WHERE user_id = v_user_id AND action_type = p_action_type
  ORDER BY window_start DESC
  LIMIT 1;

  -- Reset if window expired (1 hour)
  IF v_window_start < NOW() - INTERVAL '1 hour' THEN
    v_current_count := 0;
  END IF;

  -- Check limit
  IF v_current_count >= p_max_per_hour THEN
    RETURN FALSE;
  END IF;

  -- Increment counter
  UPDATE rate_limits 
  SET count = count + 1, window_start = NOW()
  WHERE user_id = v_user_id AND action_type = p_action_type;

  -- Insert if not exists
  IF NOT FOUND THEN
    INSERT INTO rate_limits (user_id, action_type, count, window_start)
    VALUES (v_user_id, p_action_type, 1, NOW());
  END IF;

  RETURN TRUE;
END;
$$;

GRANT EXECUTE ON FUNCTION check_rate_limit TO authenticated;
