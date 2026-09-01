-- Rename "overridden" to "review_requested" now that a block is silent for
-- the end user: they can only flag it for admin review (with an optional
-- note), not self-restore the content. Existing overridden=true rows keep
-- their meaning (a review was requested / justification given).
ALTER TABLE "incidents" RENAME COLUMN "overridden" TO "review_requested";
ALTER TABLE "ai_leak_attempts" RENAME COLUMN "overridden" TO "review_requested";

-- New field for the admin's own explanation after reviewing, separate from
-- the worker's justification/note.
ALTER TABLE "incidents" ADD COLUMN "admin_note" TEXT;
ALTER TABLE "ai_leak_attempts" ADD COLUMN "admin_note" TEXT;
