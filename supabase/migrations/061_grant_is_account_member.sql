-- ============================================================
-- 061_grant_is_account_member.sql
-- Grant EXECUTE on is_account_member to anon and PUBLIC.
--
-- Why:
--   RLS policies across almost every table (profiles, accounts,
--   contacts, conversations, etc.) invoke is_account_member(account_id).
--   When unauthenticated requests arrive (or during session startup /
--   SSR before the user's token is attached), PostgreSQL evaluates
--   the table's RLS policies.
--   If the `anon` role lacks EXECUTE on is_account_member, PostgreSQL
--   fails immediately with SQLSTATE 42501 (permission denied for function
--   is_account_member).
--
-- Safety:
--   is_account_member is SECURITY DEFINER and checks:
--     WHERE p.user_id = auth.uid()
--   For anon requests, auth.uid() is NULL, so the function returns
--   false safely with no data leaked.
-- ============================================================

GRANT EXECUTE ON FUNCTION public.is_account_member(UUID, account_role_enum) TO anon, authenticated, service_role, PUBLIC;

