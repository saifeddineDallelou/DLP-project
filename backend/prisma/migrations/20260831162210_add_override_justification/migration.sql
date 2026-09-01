-- AlterTable
ALTER TABLE "ai_leak_attempts" ADD COLUMN     "justification" TEXT,
ADD COLUMN     "overridden" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "incidents" ADD COLUMN     "justification" TEXT,
ADD COLUMN     "overridden" BOOLEAN NOT NULL DEFAULT false;
