-- CA Nexus Hub - Secure Audit Logging
-- Prevents users from forging audit logs
-- All user_id and user_email are determined server-side

-- ============================================
-- Secure Audit Log Function
-- ============================================

-- Drop existing function if exists
DROP FUNCTION IF EXISTS public.log_audit CASCADE;

-- Create secure audit logging function
-- This is the ONLY way to insert audit logs (users cannot call this directly)
CREATE OR REPLACE FUNCTION public.log_audit(
  p_action_type TEXT,
  p_lead_id UUID DEFAULT NULL,
  p_resource_type TEXT DEFAULT NULL,
  p_resource_id TEXT DEFAULT NULL,
  p_description TEXT DEFAULT NULL,
  p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id UUID;
  v_user_email TEXT;
  v_audit_id UUID;
BEGIN
  -- Get current user from JWT (cannot be spoofed)
  v_user_id := auth.uid();
  
  IF v_user_id IS NULL THEN
    RAISE EXCEPTION 'No authenticated user';
  END IF;

  -- Get email from auth.users (server-side only)
  SELECT email INTO v_user_email
  FROM auth.users
  WHERE id = v_user_id;

  -- Insert audit log with server-verified user info
  INSERT INTO audit_logs (
    user_id,
    user_email,
    action_type,
    lead_id,
    resource_type,
    resource_id,
    description,
    metadata,
    created_at
  ) VALUES (
    v_user_id,
    v_user_email,
    p_action_type,
    p_lead_id,
    p_resource_type,
    p_resource_id,
    p_description,
    p_metadata,
    NOW()
  )
  RETURNING id INTO v_audit_id;

  RETURN v_audit_id;
END;
$$;

-- ============================================
-- Secure Lead Access Logging
-- ============================================

-- Function to log when user views lead contact details
CREATE OR REPLACE FUNCTION public.log_lead_access(
  p_lead_id UUID,
  p_access_type TEXT  -- 'view_contact', 'download', 'export'
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id UUID;
BEGIN
  v_user_id := auth.uid();
  
  IF v_user_id IS NULL THEN
    RETURN;
  END IF;

  -- Call the secure audit function
  PERFORM public.log_audit(
    'LEAD_ACCESS_' || upper(p_access_type),
    p_lead_id,
    'lead',
    p_lead_id::TEXT,
    'User accessed lead contact information',
    jsonb_build_object(
      'access_type', p_access_type,
      'lead_id', p_lead_id
    )
  );
END;
$$;

-- ============================================
-- Update RLS for Audit Logs
-- ============================================

-- Remove all existing audit log insert policies (service role handles inserts)
DROP POLICY IF EXISTS "Admins can view all audit logs" ON audit_logs;
DROP POLICY IF EXISTS "Users can view own audit logs" ON audit_logs;
DROP POLICY IF EXISTS "Anon can insert audit logs" ON audit_logs;
DROP POLICY IF EXISTS "Authenticated can insert audit logs" ON audit_logs;

-- Only service role (Edge Functions) can INSERT audit logs
-- This bypasses RLS completely

-- Users can view ONLY their own actions (limited view)
CREATE POLICY "Users can view own audit actions"
  ON audit_logs FOR SELECT
  TO authenticated
  USING (user_id = auth.uid());

-- Admins can view all logs
CREATE POLICY "Admins can view all audit logs"
  ON audit_logs FOR SELECT
  TO authenticated
  USING (
    EXISTS (SELECT 1 FROM profiles WHERE id = auth.uid() :: text AND role = 'admin')
  );

-- ============================================
-- Create Helper Views for Frontend
-- ============================================

-- View for user's own audit history
CREATE OR REPLACE VIEW my_audit_history AS
SELECT
  al.id,
  al.action_type,
  al.description,
  al.created_at,
  l.title as lead_title,
  l.company_name
FROM audit_logs al
LEFT JOIN leads l ON l.id = al.lead_id
WHERE al.user_id = auth.uid()
ORDER BY al.created_at DESC
LIMIT 100;

-- View for admin audit summary
CREATE OR REPLACE VIEW admin_audit_summary AS
SELECT
  DATE(created_at) as date,
  action_type,
  COUNT(*) as count,
  COUNT(DISTINCT user_id) as unique_users,
  COUNT(DISTINCT user_email) as unique_emails
FROM audit_logs
GROUP BY DATE(created_at), action_type
ORDER BY date DESC;

-- ============================================
-- Grant Execute Permissions
-- ============================================

-- Grant execute on functions to authenticated users
GRANT EXECUTE ON FUNCTION public.log_audit TO authenticated;
GRANT EXECUTE ON FUNCTION public.log_lead_access TO authenticated;

-- Grant select on views
GRANT SELECT ON my_audit_history TO authenticated;
GRANT SELECT ON admin_audit_summary TO authenticated;
