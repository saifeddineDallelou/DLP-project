const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.resolve(__dirname, '../.env.test') });

if (!process.env.DATABASE_URL.includes('dlp_db_test')) {
  throw new Error('Refusing to run tests: DATABASE_URL does not point at dlp_db_test');
}
