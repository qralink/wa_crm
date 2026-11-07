-- ============================================================
-- 060_fix_public_schema_grants.sql
-- Grant schema and table privileges to authenticated and anon roles.
--
-- Why this migration is needed:
--   When migrations are pushed to a remote Supabase instance,
--   PostgreSQL's default privileges may not automatically grant
--   SELECT/INSERT/UPDATE/DELETE on newly created tables to the
--   `authenticated` and `anon` roles.
--   PostgreSQL verifies table-level privileges before Row Level
--   Security (RLS) is evaluated, causing queries to fail with
--   SQLSTATE 42501 (permission denied for table profiles/...).
--
-- Security model:
--   Row Level Security (RLS) is enabled on all sensitive tables
--   and controls actual row visibility and mutation rights.
-- ============================================================

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

-- Grant permissions on all tables, sequences, and routines in schema public
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO anon, authenticated, service_role;

-- Ensure future tables, sequences, and routines automatically inherit these privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON ROUTINES TO anon, authenticated, service_role;

-- ============================================================
-- Re-apply explicit restrictions from previous migrations
-- ============================================================

-- 1. Migration 054: pending_message_statuses is internal, strictly service_role only
REVOKE ALL ON TABLE public.pending_message_statuses FROM anon, authenticated;

-- 2. Migration 027: notifications table only permits authenticated to UPDATE read_at
REVOKE UPDATE ON public.notifications FROM authenticated;
GRANT UPDATE (read_at) ON public.notifications TO authenticated;

-- 3. Migration 044 & related: internal definer functions restricted to service_role
REVOKE ALL ON FUNCTION public._bcast_bump(UUID, TEXT, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public._bcast_bump(UUID, TEXT, INTEGER) TO service_role;

REVOKE ALL ON FUNCTION public.recompute_broadcast_counts(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.recompute_broadcast_counts(UUID) TO service_role;

REVOKE ALL ON FUNCTION public.claim_ai_reply_slot(UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_ai_reply_slot(UUID, INTEGER) TO service_role;

REVOKE ALL ON FUNCTION public.record_webhook_failure(UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.record_webhook_failure(UUID, INTEGER) TO service_role;

REVOKE ALL ON FUNCTION public.merge_duplicate_contacts() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.merge_duplicate_contacts() TO service_role;

REVOKE ALL ON FUNCTION public.merge_duplicate_conversations() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.merge_duplicate_conversations() TO service_role;

-- 4. Inbound webhook & broadcast helper functions (037, 049) restricted to service_role
REVOKE ALL ON FUNCTION public.bump_conversation_on_inbound(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bump_conversation_on_inbound(UUID, TEXT) TO service_role;

REVOKE ALL ON FUNCTION public.create_broadcast_with_recipients(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, UUID[], JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.create_broadcast_with_recipients(UUID, UUID, TEXT, TEXT, TEXT, INTEGER, UUID[], JSONB) TO service_role;

-- 5. Execution counter functions (007, 012) restricted to service_role
REVOKE ALL ON FUNCTION public.increment_automation_execution_count(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.increment_automation_execution_count(UUID) TO service_role;

REVOKE ALL ON FUNCTION public.increment_flow_execution_count(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.increment_flow_execution_count(UUID) TO service_role;

-- 6. Internal trigger functions
REVOKE ALL ON FUNCTION public.track_conversation_message_times() FROM PUBLIC, anon, authenticated;

-- 7. Functions callable by authenticated (and service_role), but not anon
REVOKE ALL ON FUNCTION public.dashboard_overview(INTEGER, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.dashboard_overview(INTEGER, TEXT) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.replace_flow_nodes(UUID, JSONB) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.replace_flow_nodes(UUID, JSONB) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.match_ai_knowledge_fts(UUID, TEXT, INTEGER) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.match_ai_knowledge_fts(UUID, TEXT, INTEGER) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.match_ai_knowledge_semantic(UUID, TEXT, INTEGER) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.match_ai_knowledge_semantic(UUID, TEXT, INTEGER) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.set_member_role(UUID, account_role_enum) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_member_role(UUID, account_role_enum) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.remove_account_member(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.remove_account_member(UUID) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.transfer_account_ownership(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.transfer_account_ownership(UUID) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.redeem_invitation(TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.redeem_invitation(TEXT) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INT, INT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.filter_contacts_by_tags(UUID[], TEXT, INT, INT) TO authenticated, service_role;

-- is_account_member must be executable by anon/PUBLIC so that RLS policies
-- (profiles_select, accounts_select, etc.) can be evaluated for unauthenticated callers
-- without triggering SQLSTATE 42501. It safely returns false when auth.uid() is null.
GRANT EXECUTE ON FUNCTION public.is_account_member(UUID, account_role_enum) TO anon, authenticated, service_role, PUBLIC;

-- ============================================================
-- Ensure all existing users have profile + account rows bootstrapped
-- ============================================================
DO $$
BEGIN
  -- Backfill any auth.users missing a profile row
  INSERT INTO public.profiles (user_id, full_name, email)
  SELECT u.id,
         COALESCE(u.raw_user_meta_data->>'full_name', ''),
         COALESCE(u.email, '')
  FROM auth.users u
  WHERE NOT EXISTS (
    SELECT 1 FROM public.profiles p WHERE p.user_id = u.id
  );

  -- Backfill any profile missing an account row
  INSERT INTO public.accounts (name, owner_user_id)
  SELECT COALESCE(NULLIF(p.full_name, ''), NULLIF(p.email, ''), 'My account'),
         p.user_id
  FROM public.profiles p
  WHERE NOT EXISTS (
    SELECT 1 FROM public.accounts a WHERE a.owner_user_id = p.user_id
  );

  -- Ensure profile account_id and account_role are populated
  UPDATE public.profiles p
  SET account_id   = a.id,
      account_role = 'owner'
  FROM public.accounts a
  WHERE a.owner_user_id = p.user_id
    AND (p.account_id IS NULL OR p.account_role IS NULL);
END $$;

