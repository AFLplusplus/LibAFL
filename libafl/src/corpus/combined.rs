use core::{cell::RefCell, marker::PhantomData};
use std::{collections::VecDeque, rc::Rc, vec::Vec};

use libafl_bolts::Error;
use serde::{Deserialize, Serialize};

use super::{Corpus, CorpusCounter, CorpusId, Testcase, store::Store};

/// A [`CombinedCorpus`] tries first to use the main store according to some policy.
/// If it fails, it falls back to the secondary store.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CombinedCorpus<C, CS, FS, I> {
    /// The cache store
    cache_store: RefCell<CS>,
    /// The fallback store
    fallback_store: FS,
    /// The policty taking decisions
    cache: RefCell<C>,
    /// The corpus ID counter
    counter: CorpusCounter,
    /// The keys in order (use `Vec::binary_search`)
    keys: Vec<CorpusId>,
    /// The current ID
    current: Option<CorpusId>,
    phantom: PhantomData<I>,
}

pub struct FifoCache<CS, FS, I> {
    cached_ids: VecDeque<CorpusId>,
    cache_max_len: usize,
    phantom: PhantomData<(I, CS, FS)>,
}

pub struct IdentityCache;

pub trait Cache<CS, FS, I> {
    fn add(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    fn add_disabled(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error>;

    fn replace(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Testcase<I>, Error>;

    fn remove(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error>;

    fn get(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error>;

    fn get_from_all(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error>;
}

impl<CS, FS, I> FifoCache<CS, FS, I>
where
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    fn get_inner<CAF, CGF, CRF, FGF>(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
        cache_add_fn: CAF,
        cache_get_fn: CGF,
        cache_rm_fn: CRF,
        fallback_get_fn: FGF,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error>
    where
        CAF: FnOnce(&mut CS, CorpusId, Testcase<I>) -> Result<(), Error>,
        CGF: FnOnce(&CS, CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>,
        CRF: FnOnce(&mut CS, CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>,
        FGF: FnOnce(&FS, CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error>,
    {
        if self.cached_ids.contains(&id) {
            cache_get_fn(cache_store, id)
        } else {
            // tescase is not cached, fetch it from fallback
            let fb_tc = fallback_get_fn(&fallback_store, id)?;
            cache_add_fn(cache_store, id, fb_tc.borrow().clone())?;

            if self.cached_ids.len() == self.cache_max_len {
                let to_evict = self.cached_ids.pop_back().unwrap();
                cache_rm_fn(cache_store, to_evict)?;
            }

            debug_assert!(self.cached_ids.len() < self.cache_max_len);

            self.cached_ids.push_front(id);

            Ok(fb_tc)
        }
    }
}

impl<CS, FS, I> Cache<CS, FS, I> for IdentityCache
where
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    fn add(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.add(id, testcase.clone())?;
        fallback_store.add(id, testcase.clone())
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        cache_store.add_disabled(id, testcase.clone())?;
        fallback_store.add_disabled(id, testcase.clone())
    }

    fn replace(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Testcase<I>, Error> {
        cache_store.replace(id, testcase.clone())?;
        fallback_store.replace(id, testcase.clone())
    }

    fn remove(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        cache_store.remove(id)?;
        fallback_store.remove(id)
    }

    fn get(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        _fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        cache_store.get(id)
    }

    fn get_from_all(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        _fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        cache_store.get_from_all(id)
    }
}

impl<CS, FS, I> Cache<CS, FS, I> for FifoCache<CS, FS, I>
where
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    fn get(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.get_inner(
            id,
            cache_store,
            fallback_store,
            |cache_store, corpus_id, testcase| cache_store.add(corpus_id, testcase),
            |cache_store, corpus_id| cache_store.get(corpus_id),
            |cache_store, corpus_id| cache_store.remove(corpus_id),
            |fallback_store, corpus_id| fallback_store.get(corpus_id),
        )
    }

    fn get_from_all(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.get_inner(
            id,
            cache_store,
            fallback_store,
            |cache_store, corpus_id, testcase| cache_store.add(corpus_id, testcase),
            |cache_store, corpus_id| cache_store.get(corpus_id),
            |cache_store, corpus_id| cache_store.remove(corpus_id),
            |fallback_store, corpus_id| fallback_store.get_from_all(corpus_id),
        )
    }

    fn add(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        _cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        fallback_store.add(id, testcase)
    }

    fn add_disabled(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        _cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<(), Error> {
        fallback_store.add_disabled(id, testcase)
    }

    fn replace(
        &mut self,
        id: CorpusId,
        testcase: Testcase<I>,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Testcase<I>, Error> {
        if self.cached_ids.contains(&id) {
            cache_store.replace(id, testcase.clone())?;
        }

        fallback_store.replace(id, testcase)
    }

    fn remove(
        &mut self,
        id: CorpusId,
        cache_store: &mut CS,
        fallback_store: &mut FS,
    ) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        if self.cached_ids.contains(&id) {
            self.cached_ids.retain(|elt| *elt != id);
            cache_store.remove(id)?;
        }

        fallback_store.remove(id)
    }
}

impl<C, CS, FS, I> Corpus<I> for CombinedCorpus<C, CS, FS, I>
where
    C: Cache<CS, FS, I>,
    CS: Store<I>,
    FS: Store<I>,
    I: Clone,
{
    fn count(&self) -> usize {
        self.fallback_store.count()
    }

    fn count_disabled(&self) -> usize {
        self.fallback_store.count_disabled()
    }

    fn count_all(&self) -> usize {
        self.fallback_store.count_all()
    }

    fn add(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();

        self.cache.borrow_mut().add(
            new_id,
            testcase,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )?;

        Ok(new_id)
    }

    fn add_disabled(&mut self, testcase: Testcase<I>) -> Result<CorpusId, Error> {
        let new_id = self.counter.new_id();

        self.cache.borrow_mut().add_disabled(
            new_id,
            testcase,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )?;

        Ok(new_id)
    }

    fn replace(&mut self, id: CorpusId, testcase: Testcase<I>) -> Result<Testcase<I>, Error> {
        self.cache.borrow_mut().replace(
            id,
            testcase,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )
    }

    fn remove(&mut self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.cache.borrow_mut().remove(
            id,
            &mut *self.cache_store.borrow_mut(),
            &mut self.fallback_store,
        )
    }

    fn get(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.cache.borrow_mut().get(
            id,
            &mut *self.cache_store.borrow_mut(),
            &self.fallback_store,
        )
    }

    fn get_from_all(&self, id: CorpusId) -> Result<Rc<RefCell<Testcase<I>>>, Error> {
        self.cache.borrow_mut().get_from_all(
            id,
            &mut *self.cache_store.borrow_mut(),
            &self.fallback_store,
        )
    }

    fn current(&self) -> &Option<CorpusId> {
        &self.current
    }

    fn current_mut(&mut self) -> &mut Option<CorpusId> {
        &mut self.current
    }

    fn next(&self, id: CorpusId) -> Option<CorpusId> {
        self.fallback_store.next(id)
    }

    fn prev(&self, id: CorpusId) -> Option<CorpusId> {
        self.fallback_store.prev(id)
    }

    fn first(&self) -> Option<CorpusId> {
        self.fallback_store.first()
    }

    fn last(&self) -> Option<CorpusId> {
        self.fallback_store.last()
    }

    fn nth(&self, nth: usize) -> CorpusId {
        self.fallback_store.nth(nth)
    }

    fn nth_from_all(&self, nth: usize) -> CorpusId {
        self.fallback_store.nth_from_all(nth)
    }
}
