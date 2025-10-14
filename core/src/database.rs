use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::time::sleep;

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database not initialized")]
    NotInitialized,
    #[error("FS error: {0}")]
    FsError(#[from] std::io::Error),
    #[error("SQLx error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Migrate error: {0}")]
    MigrateError(#[from] sqlx::migrate::MigrateError),
}

#[derive(Clone)]
pub struct Database {
    pub pool: SqlitePool,
}

impl Database {
    pub async fn new(db_path: PathBuf, migrations_path: PathBuf) -> Result<Self, DatabaseError> {
        let db_url = format!("{}", db_path.display());

        // Create database if it doesn't exist
        eprintln!("Checking if DB exists...{:?}", db_url);
        if Sqlite::database_exists(&db_url).await.unwrap_or(false) {
            eprintln!("DB exists");
        } else {
            eprintln!("DB does not exist, creating...");
            match Sqlite::create_database(&db_url).await {
                Ok(_) => {
                    eprintln!("DB created");
                }
                Err(e) => {
                    eprintln!("Error creating DB: {:?}", e);
                }
            }
        }

        // Create connection pool with Litestream-compatible settings
        eprintln!("Creating connection pool...");
        let pool = SqlitePoolOptions::new()
            .acquire_timeout(Duration::from_secs(10)) // Increased timeout
            .max_connections(5)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    let conn = &mut *conn;
                    // Enable WAL mode for Litestream compatibility
                    sqlx::query("PRAGMA journal_mode=WAL")
                        .execute(&mut *conn)
                        .await?;
                    // Good durability/latency trade-off
                    sqlx::query("PRAGMA synchronous=NORMAL")
                        .execute(&mut *conn)
                        .await?;
                    // Let Litestream manage checkpoints
                    sqlx::query("PRAGMA wal_autocheckpoint=0")
                        .execute(&mut *conn)
                        .await?;
                    // Avoid SQLITE_BUSY thrash
                    sqlx::query("PRAGMA busy_timeout=5000")
                        .execute(&mut *conn)
                        .await?;
                    // Enable foreign keys
                    sqlx::query("PRAGMA foreign_keys=ON")
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&format!("{}?mode=rwc", db_url))
            .await?;

        // Run migrations
        eprintln!("Running migrations...");
        let mut attempts = 0;
        while attempts < 3 {
            match sqlx::migrate::Migrator::new(migrations_path.clone())
                .await?
                .run(&pool)
                .await
            {
                Ok(_) => break,
                Err(_e) if attempts < 2 => {
                    sleep(Duration::from_millis(500)).await;
                    attempts += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }

        Ok(Self { pool })
    }
}
