//! Shared leaf handles used to compose the three community facades.

/// Cloneable handle to one actual rulebook store. Give clones to cplc and cmty
/// so snapshots and decisions use the same revisions, including in memory.
pub struct SharedRulebook<R>(std::sync::Arc<R>);

impl<R> SharedRulebook<R> {
    /// Own one store; cloning shares rather than copies its state.
    pub fn new(store: R) -> Self {
        Self(std::sync::Arc::new(store))
    }
}

impl<R> Clone for SharedRulebook<R> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<R: crbk::Storage> crbk::Storage for SharedRulebook<R> {
    async fn load(
        &self,
        community: &str,
        selection: crbk::Selection,
    ) -> crbk::Result<Option<crbk::Revision>> {
        self.0.load(community, selection).await
    }

    async fn append(
        &self,
        community: &str,
        expected: Option<u64>,
        change: crbk::Change,
    ) -> crbk::Result<crbk::Revision> {
        self.0.append(community, expected, change).await
    }

    async fn append_checked<G: crbk::CommitGuard>(
        &self,
        community: &str,
        expected: Option<u64>,
        change: crbk::Change,
        guard: &mut G,
    ) -> crbk::Result<crbk::Revision> {
        // Forward the authority-checked append: the default refuses, which would
        // turn every guarded setting edit into a storage failure.
        self.0
            .append_checked(community, expected, change, guard)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crbk::Storage;

    #[derive(Default)]
    struct Probe(std::sync::atomic::AtomicBool);
    impl Storage for Probe {
        async fn load(&self, _: &str, _: crbk::Selection) -> crbk::Result<Option<crbk::Revision>> {
            Ok(None)
        }
        async fn append(
            &self,
            _: &str,
            _: Option<u64>,
            _: crbk::Change,
        ) -> crbk::Result<crbk::Revision> {
            Err(crbk::Error::Storage)
        }
        async fn append_checked<G: crbk::CommitGuard>(
            &self,
            _: &str,
            _: Option<u64>,
            _: crbk::Change,
            _: &mut G,
        ) -> crbk::Result<crbk::Revision> {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(crbk::Error::Conflict)
        }
    }
    struct Guard;
    impl crbk::CommitGuard for Guard {
        async fn check(&mut self) -> crbk::Result<()> {
            Ok(())
        }
        fn release(&mut self) -> crbk::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn shared_rulebook_forwards_the_checked_append() {
        let shared = SharedRulebook::new(Probe::default());
        let change = crbk::Change {
            rulebook: crbk::Rulebook::default(),
            announced_at: 1_800_000_001,
            effective_at: 1_800_000_001,
            notice_seconds: 0,
            policy_epoch: 1,
        };
        let result = shared
            .append_checked("c", None, change, &mut Guard)
            .await;
        assert!(matches!(result, Err(crbk::Error::Conflict)));
        assert!(shared.0.0.load(std::sync::atomic::Ordering::SeqCst));
    }
}
