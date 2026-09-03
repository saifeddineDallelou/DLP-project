-- How many times the same thing happened inside one reporting window.
--
-- One row saying attempts=10 beats ten rows saying the same thing, which is
-- how a triage queue stops being read at all. Defaults to 1, so every
-- existing row keeps meaning exactly what it meant.
ALTER TABLE "incidents" ADD COLUMN IF NOT EXISTS "attempts" INTEGER NOT NULL DEFAULT 1;
