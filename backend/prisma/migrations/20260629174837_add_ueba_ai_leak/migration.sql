-- CreateEnum
CREATE TYPE "BehaviorEventType" AS ENUM ('FILE_ACCESS', 'USB_INSERT', 'CLIPBOARD_COPY', 'SCREENSHOT', 'APP_LAUNCH', 'AFTER_HOURS_ACCESS');

-- CreateEnum
CREATE TYPE "AiPlatform" AS ENUM ('CHATGPT', 'CLAUDE', 'GEMINI', 'COPILOT', 'OTHER');

-- CreateEnum
CREATE TYPE "LeakMethod" AS ENUM ('CLIPBOARD', 'SCREENSHOT', 'BROWSER', 'EXTENSION');

-- CreateTable
CREATE TABLE "user_behavior_baselines" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "avg_daily_files" DOUBLE PRECISION NOT NULL,
    "avg_daily_volume_mb" DOUBLE PRECISION NOT NULL,
    "avg_working_hour_start" INTEGER NOT NULL,
    "avg_working_hour_end" INTEGER NOT NULL,
    "avg_usb_frequency" DOUBLE PRECISION NOT NULL,
    "risk_score" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "last_updated" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user_behavior_baselines_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "behavior_events" (
    "id" TEXT NOT NULL,
    "agent_id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "event_type" "BehaviorEventType" NOT NULL,
    "metadata" JSONB NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "behavior_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ai_leak_attempts" (
    "id" TEXT NOT NULL,
    "agent_id" TEXT NOT NULL,
    "platform" "AiPlatform" NOT NULL,
    "method" "LeakMethod" NOT NULL,
    "content_sample" TEXT,
    "risk_score" DOUBLE PRECISION NOT NULL,
    "blocked" BOOLEAN NOT NULL DEFAULT true,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_leak_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_behavior_baselines_user_id_key" ON "user_behavior_baselines"("user_id");

-- AddForeignKey
ALTER TABLE "user_behavior_baselines" ADD CONSTRAINT "user_behavior_baselines_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "behavior_events" ADD CONSTRAINT "behavior_events_agent_id_fkey" FOREIGN KEY ("agent_id") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ai_leak_attempts" ADD CONSTRAINT "ai_leak_attempts_agent_id_fkey" FOREIGN KEY ("agent_id") REFERENCES "agents"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
