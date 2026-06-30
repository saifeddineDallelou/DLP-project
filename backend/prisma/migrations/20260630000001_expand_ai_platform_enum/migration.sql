-- Migration: expand_ai_platform_enum
-- Converts the AiPlatform enum to a comprehensive list of AI platforms.
-- Existing rows are remapped before the type change.

-- Step 1: Relax column to plain text so UPDATE runs freely
ALTER TABLE "ai_leak_attempts" ALTER COLUMN "platform" TYPE TEXT;

-- Step 2: Remap old values → new enum names
UPDATE "ai_leak_attempts" SET "platform" = 'OPENAI_CHATGPT'    WHERE "platform" = 'CHATGPT';
UPDATE "ai_leak_attempts" SET "platform" = 'ANTHROPIC_CLAUDE'  WHERE "platform" = 'CLAUDE';
UPDATE "ai_leak_attempts" SET "platform" = 'GOOGLE_GEMINI'     WHERE "platform" = 'GEMINI';
UPDATE "ai_leak_attempts" SET "platform" = 'MICROSOFT_COPILOT' WHERE "platform" = 'COPILOT';
UPDATE "ai_leak_attempts" SET "platform" = 'OTHER_AI'          WHERE "platform" = 'OTHER';

-- Step 3: Drop old enum
DROP TYPE "AiPlatform";

-- Step 4: Create new comprehensive enum
CREATE TYPE "AiPlatform" AS ENUM (
  'OPENAI_CHATGPT',
  'ANTHROPIC_CLAUDE',
  'GOOGLE_GEMINI',
  'MICROSOFT_COPILOT',
  'PERPLEXITY',
  'POE',
  'CHARACTER_AI',
  'MISTRAL',
  'GROK',
  'META_AI',
  'DEEPSEEK',
  'HUGGINGFACE',
  'YOU_COM',
  'PI_AI',
  'GROQ',
  'COHERE',
  'OTHER_AI'
);

-- Step 5: Cast column back to the new enum type
ALTER TABLE "ai_leak_attempts"
  ALTER COLUMN "platform" TYPE "AiPlatform"
  USING "platform"::"AiPlatform";
