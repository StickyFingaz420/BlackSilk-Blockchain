import { Database } from './database-new';

async function setup() {
  try {
    console.log('Initializing database...');
    const db = Database.getInstance();
    await db.initialize();
    console.log('Database initialized successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
}

setup();
