-- A file in flight is its own channel.
--
-- The policy layer has named FILE_UPLOAD since per-channel responses existed:
-- it is what separates a file sitting in a watched folder, which can only be
-- quarantined, from a file being sent somewhere, which can be stopped. The
-- enum never caught up, so the first code to record an upload incident failed
-- at the database with the block already applied -- the worst shape of
-- failure, since the user was stopped and nothing was written down.
ALTER TYPE "Channel" ADD VALUE IF NOT EXISTS 'FILE_UPLOAD';
