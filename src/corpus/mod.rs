pub mod testcase;
pub use testcase::{Testcase, TestcaseMetadata};

use alloc::borrow::ToOwned;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::path::PathBuf;

use crate::inputs::Input;
use crate::utils::{HasRand, Rand};
use crate::AflError;

pub trait HasEntriesVec<I>
where
    I: Input,
{
    /// Get the entries vector field
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>];

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>>;
}

/// Corpus with all current testcases
pub trait Corpus<I>: HasEntriesVec<I> + HasRand
where
    I: Input,
{
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.entries().len()
    }

    /// Add an entry to the corpus
    fn add(&mut self, testcase: Rc<RefCell<Testcase<I>>>) {
        self.entries_mut().push(testcase);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Rc<RefCell<Testcase<I>>>> {
        let mut i: usize = 0;
        let mut found = false;
        for x in self.entries() {
            i = i + 1;
            if &*x.borrow() as *const _ == entry as *const _ {
                // TODO check if correct
                found = true;
                break;
            }
        }
        if !found {
            return None;
        }
        Some(self.entries_mut().remove(i))
    }

    /// Gets a random entry
    fn random_entry(&self) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        if self.count() == 0 {
            Err(AflError::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = self.rand_below(len as u64) as usize;
            Ok((self.entries()[id].clone(), id))
        }
    }

    // TODO: IntoIter
    /// Gets the next entry
    fn next(&mut self) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        self.random_entry()
    }
}

pub struct InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    rand: Rc<RefCell<R>>,
    entries: Vec<Rc<RefCell<Testcase<I>>>>,
}

impl<I, R> HasEntriesVec<I> for InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>] {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>> {
        &mut self.entries
    }
}

impl<I, R> HasRand for InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

impl<I, R> Corpus<I> for InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    // Just use the default implementation
}

impl<I, R> InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    pub fn new(rand: &Rc<RefCell<R>>) -> Self {
        InMemoryCorpus {
            rand: Rc::clone(rand),
            entries: vec![],
        }
    }
}

#[cfg(feature = "std")]
pub struct OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    rand: Rc<RefCell<R>>,
    entries: Vec<Rc<RefCell<Testcase<I>>>>,
    dir_path: PathBuf,
}

#[cfg(feature = "std")]
impl<I, R> HasEntriesVec<I> for OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>] {
        &self.entries
    }
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>> {
        &mut self.entries
    }
}

#[cfg(feature = "std")]
impl<I, R> HasRand for OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

#[cfg(feature = "std")]
impl<I, R> Corpus<I> for OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    /// Add an entry and save it to disk
    fn add(&mut self, entry: Rc<RefCell<Testcase<I>>>) {
        if *entry.borrow().filename() == None {
            // TODO walk entry metadatas to ask for pices of filename (e.g. :havoc in AFL)
            let filename = self.dir_path.join(format!("id_{}", &self.entries.len()));
            let filename_str = filename.to_str().expect("Invalid Path");
            *entry.borrow_mut().filename_mut() = Some(filename_str.into());
        }
        self.entries.push(entry);
    }

    // TODO save and remove files, cache, etc..., ATM use just InMemoryCorpus
}

#[cfg(feature = "std")]
impl<I, R> OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    pub fn new(rand: &Rc<RefCell<R>>, dir_path: PathBuf) -> Self {
        OnDiskCorpus {
            rand: Rc::clone(rand),
            dir_path: dir_path,
            entries: vec![],
        }
    }
}

/// A Queue-like corpus, wrapping an existing Corpus instance
pub struct QueueCorpus<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    corpus: C,
    phantom: PhantomData<I>,
    pos: usize,
    cycles: u64,
}

impl<'a, I, C> HasEntriesVec<I> for QueueCorpus<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>] {
        self.corpus.entries()
    }
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>> {
        self.corpus.entries_mut()
    }
}

impl<'a, I, C> HasRand for QueueCorpus<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    type R = C::R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        self.corpus.rand()
    }
}

impl<'a, I, C> Corpus<I> for QueueCorpus<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    /// Returns the number of elements
    fn count(&self) -> usize {
        self.corpus.count()
    }

    fn add(&mut self, entry: Rc<RefCell<Testcase<I>>>) {
        self.corpus.add(entry);
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Rc<RefCell<Testcase<I>>>> {
        self.corpus.remove(entry)
    }

    /// Gets a random entry
    fn random_entry(&self) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        self.corpus.random_entry()
    }

    /// Gets the next entry
    fn next(&mut self) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        self.pos += 1;
        if self.corpus.count() == 0 {
            return Err(AflError::Empty("Corpus".to_owned()));
        }
        if self.pos > self.corpus.count() {
            // TODO: Always loop or return informational error?
            self.pos = 1;
            self.cycles += 1;
        }
        Ok((self.corpus.entries()[self.pos - 1].clone(), self.pos - 1))
    }
}

impl<'a, I, C> QueueCorpus<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    pub fn new(corpus: C) -> Self {
        QueueCorpus::<I, C> {
            corpus: corpus,
            phantom: PhantomData,
            cycles: 0,
            pos: 0,
        }
    }

    pub fn cycles(&self) -> u64 {
        self.cycles
    }

    pub fn pos(&self) -> usize {
        self.pos
    }
}

/* TODO: Iterator corpus, like:

enum MutationAction {
    ReplaceInput(old_ref, new_val),
    AppendNewInput(new_val),
}

struct NewCorpus {
    testcases: Vec<NewTestCase>,
    offset: usize;
}

impl NewCorpus {

    pub fn handle_mutation(&mut self, action: MutationAction) {
        match action {
            MutationAction::ReplaceInput() => {},
            MutationAction::AppendNewInput() => {},
        }
    }
}

impl Iterator for NewCorpus {
    type Item = NewTestCase;

    fn next(&mut self) -> Option<&Self::Item> {
        // FIXME: implement next here
        self.offset = 3;

        // When no more stuff, return None
        None
    }
}

And then:

    corpus.iter()
        .mutate_foo()
        .mutate_bar()
        .set_observer(obs)
        .execute_binary(|input| {
            ...
        })
        .map(|observers, input, mutators| match result {
            /// do things  depending on coverage, etc...
            e.g. corpus.handle_mutation(MutationAction::AppendNewInput)
        })
*/

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use crate::corpus::Corpus;
    use crate::corpus::Testcase;
    use crate::corpus::{OnDiskCorpus, QueueCorpus};
    use crate::inputs::bytes::BytesInput;
    use crate::utils::DefaultRand;

    use alloc::rc::Rc;
    use std::path::PathBuf;

    #[test]
    fn test_queuecorpus() {
        let rand: Rc<_> = DefaultRand::new(0).into();
        let mut q = QueueCorpus::new(OnDiskCorpus::new(&rand, PathBuf::from("fancy/path")));
        let t: Rc<_> =
            Testcase::with_filename(BytesInput::new(vec![0 as u8; 4]), "fancyfile".into()).into();
        q.add(t);
        let filename = q
            .next()
            .unwrap()
            .0
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .to_owned();
        assert_eq!(
            filename,
            q.next()
                .unwrap()
                .0
                .borrow()
                .filename()
                .as_ref()
                .unwrap()
                .to_owned()
        );
        assert_eq!(filename, "fancyfile");
    }
}
