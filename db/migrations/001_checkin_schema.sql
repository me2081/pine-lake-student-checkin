CREATE TABLE IF NOT EXISTS public.checkin_students (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS checkin_students_active_name_uq
  ON public.checkin_students (lower(name)) WHERE active = true;

CREATE TABLE IF NOT EXISTS public.checkin_attendance (
  id uuid PRIMARY KEY,
  student_id uuid REFERENCES public.checkin_students(id) ON DELETE SET NULL,
  student_name text NOT NULL,
  action text NOT NULL CHECK (action IN ('check-in', 'check-out')),
  occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS checkin_attendance_student_time_idx
  ON public.checkin_attendance (student_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS public.checkin_admin_credentials (
  id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  salt text NOT NULL,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.checkin_login_attempts (
  ip_hash text PRIMARY KEY,
  attempts integer NOT NULL DEFAULT 0,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz
);

GRANT USAGE ON SCHEMA public TO checkin_app;
GRANT SELECT, INSERT, UPDATE, DELETE
  ON public.checkin_students, public.checkin_attendance,
     public.checkin_admin_credentials, public.checkin_login_attempts
  TO checkin_app;
