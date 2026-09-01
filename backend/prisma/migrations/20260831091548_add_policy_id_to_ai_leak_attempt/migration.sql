-- AlterTable
ALTER TABLE "ai_leak_attempts" ADD COLUMN     "policy_id" TEXT;

-- AddForeignKey
ALTER TABLE "ai_leak_attempts" ADD CONSTRAINT "ai_leak_attempts_policy_id_fkey" FOREIGN KEY ("policy_id") REFERENCES "policies"("id") ON DELETE SET NULL ON UPDATE CASCADE;
