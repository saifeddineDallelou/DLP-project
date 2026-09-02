-- AlterTable
ALTER TABLE "ai_leak_attempts" ADD COLUMN     "attempts" INTEGER NOT NULL DEFAULT 1,
ADD COLUMN     "last_attempt_at" TIMESTAMP(3);
