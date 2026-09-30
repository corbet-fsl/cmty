//! Shared leaf handles used to compose the three community facades.

/// Cloneable handle to one actual rulebook store. Give clones to cplc and cmnt
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
}
