import { DataSource } from "typeorm";
import { createSchema } from "./schema.js";
import { User } from "src/users/user.entity.js";

const datasorce = new DataSource({
  type: 'postgres',
  host: process.env.DATABASE_HOST || 'localhost',
  port: parseInt(process.env.DATABASE_PORT || '5432', 10),
  username: process.env.DATABASE_USER || 'root',
  password: process.env.DATABASE_PASSWORD || '12345678',
  database: process.env.DATABASE_NAME || 'vulnlab',
  entities: [User],
  synchronize: true,

});

datasorce
  .initialize()
  .then(async () => {
    await createSchema(datasorce);
    console.log('Seeding completed.');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Error during Data Source initialization:', error);
    process.exit(1);
  })
