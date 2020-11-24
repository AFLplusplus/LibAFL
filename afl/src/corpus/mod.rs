pub mod testcase;
pub use testcase::{Testcase, TestcaseMetadata};

use alloc::borrow::ToOwned;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::path::PathBuf;

use crate::AflError;
use crate::inputs::Input;
use crate::utils::Rand;

pub trait HasTestcaseVec<I>
where
    I: Input,
{
    /// Get the entries vector field
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>];

    /// Get the entries vector field (mutable)
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>>;
}

/// Corpus with all current testcases
pub trait Corpus<I, R>: HasTestcaseVec<I>
where
    I: Input,
    R: Rand,
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
    fn random_entry(&self, rand: &mut R) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        if self.count() == 0 {
            Err(AflError::Empty("No entries in corpus".to_owned()))
        } else {
            let len = { self.entries().len() };
            let id = rand.below(len as u64) as usize;
            Ok((self.entries()[id].clone(), id))
        }
    }

    // TODO: IntoIter
    /// Gets the next entry
    fn next(&mut self, rand: &mut R) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        self.random_entry(rand)
    }
}

pub trait HasCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Get the corpus field
    fn corpus(&self) -> &C;

    /// Get thecorpus field (mutable)
    fn corpus_mut(&mut self) -> &mut C;
}

pub struct InMemoryCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    entries: Vec<Rc<RefCell<Testcase<I>>>>,
    phantom: PhantomData<R>,
}

impl<I, R> HasTestcaseVec<I> for InMemoryCorpus<I, R>
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

impl<I, R> Corpus<I, R> for InMemoryCorpus<I, R>
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
    pub fn new() -> Self {
        InMemoryCorpus {
            entries: vec![],
            phantom: PhantomData,
        }
    }
}

#[cfg(feature = "std")]
pub struct OnDiskCorpus<I, R>
where
    I: Input,
    R: Rand,
{
    entries: Vec<Rc<RefCell<Testcase<I>>>>,
    dir_path: PathBuf,
    phantom: PhantomData<R>,
}

#[cfg(feature = "std")]
impl<I, R> HasTestcaseVec<I> for OnDiskCorpus<I, R>
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
impl<I, R> Corpus<I, R> for OnDiskCorpus<I, R>
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
    pub fn new(dir_path: PathBuf) -> Self {
        OnDiskCorpus {
            dir_path: dir_path,
            entries: vec![],
            phantom: PhantomData,
        }
    }
}

/// A Queue-like corpus, wrapping an existing Corpus instance
pub struct QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    corpus: C,
    pos: usize,
    cycles: u64,
    phantom: PhantomData<(I, R)>,
}

impl<C, I, R> HasTestcaseVec<I> for QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn entries(&self) -> &[Rc<RefCell<Testcase<I>>>] {
        self.corpus.entries()
    }
    fn entries_mut(&mut self) -> &mut Vec<Rc<RefCell<Testcase<I>>>> {
        self.corpus.entries_mut()
    }
}

impl<C, I, R> Corpus<I, R> for QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
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
    fn random_entry(&self, rand: &mut R) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
        self.corpus.random_entry(rand)
    }

    /// Gets the next entry
    fn next(&mut self, _rand: &mut R) -> Result<(Rc<RefCell<Testcase<I>>>, usize), AflError> {
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

impl<C, I, R> QueueCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new(corpus: C) -> Self {
        QueueCorpus {
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
    use crate::utils::StdRand;

    use alloc::rc::Rc;
    use std::path::PathBuf;

    #[test]
    fn test_queuecorpus() {
        let mut rand = StdRand::new(0);
        let mut q = QueueCorpus::new(OnDiskCorpus::<BytesInput, StdRand>::new(PathBuf::from(
            "fancy/path",
        )));
        let t: Rc<_> =
            Testcase::with_filename(BytesInput::new(vec![0 as u8; 4]), "fancyfile".into()).into();
        q.add(t);
        let filename = q
            .next(&mut rand)
            .unwrap()
            .0
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .to_owned();
        assert_eq!(
            filename,
            q.next(&mut rand)
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
