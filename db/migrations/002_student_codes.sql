-- Add per-student 3-digit codes for the public tablet check-in screen.
DO $$
BEGIN
  IF (SELECT count(*) FROM public.checkin_students) > 999 THEN
    RAISE EXCEPTION '3-digit student codes support up to 999 students';
  END IF;
END
$$;

ALTER TABLE public.checkin_students ADD COLUMN IF NOT EXISTS student_code text;

-- Assign unique starter codes to any students already in the database.
WITH numbered AS (
  SELECT id, row_number() OVER (ORDER BY created_at, id) AS n
  FROM public.checkin_students
  WHERE student_code IS NULL
)
UPDATE public.checkin_students AS s
SET student_code = lpad(numbered.n::text, 3, '0')
FROM numbered
WHERE s.id = numbered.id;

CREATE UNIQUE INDEX IF NOT EXISTS checkin_students_student_code_uq
  ON public.checkin_students (student_code);

ALTER TABLE public.checkin_students ALTER COLUMN student_code SET NOT NULL;
ALTER TABLE public.checkin_students
  ADD CONSTRAINT checkin_students_student_code_format
  CHECK (student_code ~ '^[0-9]{3}$');

CREATE TABLE IF NOT EXISTS public.checkin_code_attempts (
  ip_hash text PRIMARY KEY,
  attempts integer NOT NULL DEFAULT 0,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.checkin_code_attempts TO checkin_app;
