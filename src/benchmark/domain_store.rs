use super::DomainStats;

// Small pages bound insertion work without moving existing domain statistics.
const PAGE_LEN: usize = 4;
type Page = [Option<DomainStats>; PAGE_LEN];

#[derive(Default)]
pub(crate) struct DomainStore {
    pages: Vec<Option<Box<Page>>>,
}

impl DomainStore {
    pub(crate) fn reserve_domains(&mut self, domains: usize) {
        let pages = domains.div_ceil(PAGE_LEN);
        if pages > self.pages.len() {
            self.pages.resize_with(pages, || None);
        }
    }

    pub(crate) fn get_or_insert(&mut self, index: usize) -> &mut DomainStats {
        let page = index / PAGE_LEN;
        if page >= self.pages.len() {
            self.pages.resize_with(page + 1, || None);
        }
        self.pages[page].get_or_insert_with(|| Box::new([const { None }; PAGE_LEN]))
            [index % PAGE_LEN]
            .get_or_insert_with(DomainStats::default)
    }

    pub(crate) fn remove(&mut self, index: &usize) -> Option<DomainStats> {
        self.pages.get_mut(index / PAGE_LEN)?.as_mut()?[index % PAGE_LEN].take()
    }

    pub(crate) fn into_entries(self) -> impl Iterator<Item = (usize, DomainStats)> {
        self.pages
            .into_iter()
            .enumerate()
            .flat_map(|(page, slots)| {
                slots
                    .into_iter()
                    .flat_map(|slots| (*slots).into_iter())
                    .enumerate()
                    .filter_map(move |(slot, stats)| {
                        stats.map(|stats| (page * PAGE_LEN + slot, stats))
                    })
            })
    }

    #[cfg(test)]
    pub(crate) fn get_mut(&mut self, index: &usize) -> Option<&mut DomainStats> {
        self.pages.get_mut(index / PAGE_LEN)?.as_mut()?[index % PAGE_LEN].as_mut()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, index: &usize) -> Option<&DomainStats> {
        self.pages.get(index / PAGE_LEN)?.as_ref()?[index % PAGE_LEN].as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_pages_preserve_indices_and_move_statistics_once() {
        let mut store = DomainStore::default();
        store.reserve_domains(10_000);
        for index in [0, 3, 4, 9_999] {
            store.get_or_insert(index).attempted = index as u64 + 1;
        }
        assert_eq!(store.pages.iter().filter(|page| page.is_some()).count(), 3);
        assert_eq!(store.remove(&4).unwrap().attempted, 5);
        assert!(store.remove(&4).is_none());
        assert!(store.remove(&10_000).is_none());
        let entries: Vec<_> = store
            .into_entries()
            .map(|(index, stats)| (index, stats.attempted))
            .collect();
        assert_eq!(entries, [(0, 1), (3, 4), (9_999, 10_000)]);
    }

    #[test]
    fn preallocated_directory_does_not_grow_during_recording() {
        let mut store = DomainStore::default();
        store.reserve_domains(100_000);
        let directory = store.pages.as_ptr();
        let capacity = store.pages.capacity();
        for index in 0..100_000 {
            store.get_or_insert(index).responses += 1;
        }
        assert_eq!(store.pages.as_ptr(), directory);
        assert_eq!(store.pages.capacity(), capacity);
        assert_eq!(store.into_entries().count(), 100_000);
    }
}
