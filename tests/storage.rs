//! Shared storage contracts against memory, local libSQL, and optional Turso.

use cmnt::{Error, storage::*};
use cpsd::{ChallengeRecord, ChallengeStore, CommunityId};

fn scope(name: &str) -> CommunityId {
    CommunityId::new(name).unwrap()
}

fn record(n: u8, expires: u64) -> ChallengeRecord {
    ChallengeRecord {
        nonce: [n; 32],
        binding: [n + 1; 32],
        expires,
    }
}

async fn database() -> (tempfile::TempDir, crlt::Db, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("state.db").display());
    let db = crlt::Db::open(crlt::Config::new(url.clone(), ""))
        .await
        .unwrap();
    assert_eq!(
        db.migrate(&[crlt::Migration::new(1, "challenges", SCHEMA)])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        db.migrate(&[crlt::Migration::new(1, "challenges", SCHEMA)])
            .await
            .unwrap(),
        0
    );
    (dir, db, url)
}

async fn contract(storage: &impl Storage) {
    let a = storage.challenges();
    let b = storage.challenges();
    assert!(a.reserve(record(1, 200)).await.unwrap());
    assert!(!b.reserve(record(1, 300)).await.unwrap());
    assert!(!b.consume([1; 32], [8; 32], 100).await.unwrap());
    assert!(b.consume([1; 32], [2; 32], 200).await.unwrap());
    assert!(!a.consume([1; 32], [2; 32], 200).await.unwrap());
    assert!(a.reserve(record(2, 300)).await.unwrap());
    assert!(a.reserve(record(3, 400)).await.unwrap());
    assert_eq!(a.prune(300).await.unwrap(), 0);
    assert_eq!(b.prune(301).await.unwrap(), 1);
    assert_eq!(a.prune(401).await.unwrap(), 1);
}

#[tokio::test]
async fn memory_and_libsql_share_atomic_leaf_contract() {
    contract(&MemoryStorage::new(scope("example"), 4).unwrap()).await;
    let (_dir, db, _) = database().await;
    let storage = LibsqlStorage::new(&db, scope("example"), 4).unwrap();
    contract(&storage).await;
    storage.check_indexes().await.unwrap();
}

#[tokio::test]
async fn namespaces_reopen_capacity_and_missing_schema_fail_closed() {
    let (_dir, db, url) = database().await;
    let a = LibsqlStorage::new(&db, scope("a"), 1).unwrap().challenges();
    let b = LibsqlStorage::new(&db, scope("b"), 1).unwrap().challenges();
    assert!(a.reserve(record(1, 100)).await.unwrap());
    assert!(!b.consume([1; 32], [2; 32], 99).await.unwrap());
    assert_eq!(b.prune(101).await.unwrap(), 0);
    assert_eq!(
        a.reserve(record(2, 100)).await,
        Err(cpsd::Error::StorageCapacity)
    );
    let db2 = crlt::Db::open(crlt::Config::new(url, "")).await.unwrap();
    db2.migrate(&[crlt::Migration::new(1, "challenges", SCHEMA)])
        .await
        .unwrap();
    let c = LibsqlStorage::new(&db2, scope("a"), 1)
        .unwrap()
        .challenges();
    let (x, y) = tokio::join!(
        a.consume([1; 32], [2; 32], 100),
        c.consume([1; 32], [2; 32], 100)
    );
    assert_eq!(usize::from(x.unwrap()) + usize::from(y.unwrap()), 1);
    assert!(c.reserve(record(2, 200)).await.unwrap());
    assert!(MemoryStorage::new(scope("bad"), 0).is_err());
    assert!(LibsqlStorage::new(&db, scope("bad"), 0).is_err());

    let dir = tempfile::tempdir().unwrap();
    let raw = crlt::Db::open(crlt::Config::new(
        format!("file://{}", dir.path().join("unmigrated.db").display()),
        "",
    ))
    .await
    .unwrap();
    let bad = LibsqlStorage::new(&raw, scope("private-scope"), 1).unwrap();
    let error: Error = bad
        .challenges()
        .reserve(record(1, 100))
        .await
        .unwrap_err()
        .into();
    assert_eq!(error, Error::Storage);
    assert!(!format!("{error:?} {error}").contains("private-scope"));
}

#[tokio::test]
async fn optional_real_turso() {
    let credentials = std::env::var("TURSO_URL")
        .ok()
        .zip(std::env::var("TURSO_TOKEN").ok());
    let Some((url, token)) =
        credentials.filter(|(url, token)| !url.trim().is_empty() && !token.trim().is_empty())
    else {
        eprintln!("skipped: TURSO_URL and TURSO_TOKEN must both be set");
        return;
    };
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    db.migrate(&[crlt::Migration::new(1, "challenges", SCHEMA)])
        .await
        .unwrap();
    use cpsd::rand::RngCore;
    let mut random = [0u8; 32];
    cpsd::rand::rngs::OsRng.fill_bytes(&mut random);
    let storage = LibsqlStorage::new(&db, CommunityId::new(random).unwrap(), 4).unwrap();
    contract(&storage).await;
    storage.check_indexes().await.unwrap();
}
