-- Add per-student codes for the public tablet check-in screen.
ALTER TABLE public.checkin_students ADD COLUMN IF NOT EXISTS student_code text;

-- Assign unique 6-digit starter codes to any students already in the database.
WITH numbered AS (
  SELECT id, row_number() OVER (ORDER BY created_at, id) AS n
  FROM public.checkin_students
  WHERE student_code IS NULL
)
UPDATE public.checkin_students AS s
SET student_code = lpad(numbered.n::text, 6, '0')
FROM numbered
WHERE s.id = numbered.id;

CREATE UNIQUE INDEX IF NOT EXISTS checkin_students_student_code_uq
  ON public.checkin_students (student_code);

ALTER TABLE public.checkin_students ALTER COLUMN student_code SET NOT NULL;

CREATE TABLE IF NOT EXISTS public.checkin_code_attempts (
  ip_hash text PRIMARY KEY,
  attempts integer NOT NULL DEFAULT 0,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.checkin_code_attempts TO checkin_app;
