# Yellow Garden POS

## Local setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and set `DATABASE_URL`.
4. Start the API with `python3 -m uvicorn app.main:app --reload`.
5. Serve `frontend/` on port `5500` for local browser access.

The database user must be able to create tables during initial setup. Existing
databases are updated by `app.database` at startup, including the product
archive column and removal of the legacy product-type constraint.

## Production configuration

Set these values in the deployment environment:

- `APP_ENV=production`
- `DATABASE_URL` to the production PostgreSQL connection string
- `JWT_SECRET_KEY` to a unique random value of at least 32 characters
- `CORS_ORIGINS` to the exact HTTPS frontend origin, without `null`

Run the checked-in SQL migration before deploying to an existing database:

```bash
psql "$DATABASE_URL" -f migrations/001_product_archive.sql
```

Back up PostgreSQL before applying schema changes. Keep `.env`, `.venv/`, and
local caches out of version control; `.gitignore` includes these paths.