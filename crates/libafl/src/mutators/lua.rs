//! This module implements the [`LuaMutator`], where each mutation drops into a Lua VM to mutate bytes in a target-specific way.
#[cfg(feature = "std")]
use alloc::boxed::Box;
use alloc::{
    borrow::Cow,
    rc::Rc,
    string::{String, ToString},
    vec::Vec,
};
use core::cell::Cell;
#[cfg(feature = "std")]
use std::{fs, path::Path};

#[cfg(all(feature = "lua_mutator", feature = "std"))]
use libafl_bolts::rands::StdRand;
use libafl_bolts::{Error, Named, rands::Rand};
use mlua::{Function, HookTriggers, Lua, VmState, prelude::LuaError};

use super::MutationResult;
use crate::{
    HasMetadata,
    corpus::CorpusId,
    inputs::{HasMutatorBytes, ResizableMutator},
    mutators::Mutator,
    state::{HasMaxSize, HasRand},
};

// Note: Loops including, and above, ~400 instructions never trigger in LuaJIT due to jitting.
/// How many steps to take before timeout-ing from a mutator
const DEFAULT_TIMEOUT_STEPS: u32 = 1_000_000;

/// Converts a [`LuaError`] to a libafl-native [`Error`]
#[allow(clippy::needless_pass_by_value)] // We need this signature for `.map_error`
fn convert_error(err: LuaError) -> Error {
    Error::illegal_argument(format!("Lua execution returned error: {err:?}"))
}

/// Create an initial Rng with a fixed state..
#[cfg(all(feature = "lua_mutator", feature = "std"))]
struct RandState(StdRand);
#[cfg(all(feature = "lua_mutator", feature = "std"))]
impl HasRand for RandState {
    type Rand = StdRand;
    fn rand(&self) -> &Self::Rand {
        &self.0
    }
    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.0
    }
}

/// Load the list of lua mutators from a given folder
#[cfg(all(feature = "lua_mutator", feature = "std"))]
pub fn load_lua_mutations<
    I: HasMutatorBytes + ResizableMutator<u8>,
    S: HasMetadata + HasRand + HasMaxSize,
>(
    lua_path: &Path,
) -> Result<Vec<Box<dyn Mutator<I, S>>>, Error> {
    let mut mutations: Vec<Box<dyn Mutator<I, S>>> = vec![];
    let mut rand_state = RandState(StdRand::with_seed(1337));

    let mut paths = Vec::new();
    for entry in fs::read_dir(lua_path)? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lua"))
            && path.is_file()
        {
            paths.push(path);
        }
    }
    paths.sort();

    for path in paths {
        log::info!("Loading lua_mutator from {}", path.display());
        let name = format!(
            "LuaMutator:{}",
            path.file_stem().unwrap_or_default().to_string_lossy()
        );
        match fs::read_to_string(&path)
            .map_err(Error::from)
            .and_then(|src| LuaMutator::eat_errors(&mut rand_state, &src))
        {
            Ok(mutator) => mutations.push(Box::new(mutator.with_name(name))),
            Err(err) => log::warn!("Mutator {} did not run: {err:?}", path.display()),
        }
    }
    Ok(mutations)
}

/// Creates a new [`Lua`] VM, sets the seed using the provided rng state,
/// creates a function from the provided string, and (optionally) executes it once.
/// Return the function and a timeout tracker bool that you should set to `false` before running a function
/// Since the VM keeps counting, this bool is needed to know that we started a new execution.
/// So, in practice, the timeout / instruction counter has to trigger twice to exit execution.
/// The `timeout_steps_min` are the minimum amount of steps until execution quits.
/// In practice, the amount of steps might be up to `2x` that value.
fn create_lua_fn<S: HasRand>(
    lua: &Lua,
    state: &mut S,
    mutator_lua_fn: &str,
    timeout_steps_min: Option<u32>,
    test: bool,
) -> Result<(Function, Rc<Cell<bool>>), Error> {
    let lua_seed = state.rand_mut().next() as u32;

    let timeouted_once = Rc::new(Cell::new(false));
    let timeouted_once_cb = timeouted_once.clone();

    // Seed
    lua.load(format!("math.randomseed({lua_seed})"))
        .exec()
        .map_err(convert_error)?;

    // Set hook for timeout steps
    if let Some(timeout_steps_min) = timeout_steps_min {
        let hook_triggers = HookTriggers::new().every_nth_instruction(timeout_steps_min);

        lua.set_hook(hook_triggers, move |_lua, _debug| {
            log::trace!("I'm here. Timeouted_once: {timeouted_once_cb:?}");
            if timeouted_once_cb.replace(true) {
                Err(mlua::Error::RuntimeError(
                    "Instruction limit reached!".to_string(),
                ))
            } else {
                Ok(VmState::Continue)
            }
        })
        .map_err(convert_error)?;
    }

    let chunk = lua.load(mutator_lua_fn);

    let mutator: Function = chunk.eval().map_err(convert_error)?;

    // Simple test that the mutator works
    if test {
        timeouted_once.set(false);
        let bytes = vec![1_u8, 2, 3, 4, 5, 6, 7, 8, 9];
        drop(mutator.call::<Vec<u8>>((bytes,)).map_err(convert_error)?);
    }
    Ok((mutator, timeouted_once))
}

/// Inserts a random token at a random position in the `Input`.
pub struct LuaMutator {
    /// The Lua VM
    #[allow(dead_code)] // We need to keep a handle around.
    lua: Lua,
    /// Name of this mutator instance
    name: Cow<'static, str>,
    /// The function string we loaded
    func: String,
    /// The actual lua function we can call
    mutator: Function,
    /// If we should get rid of errors
    eat_errors: bool,
    /// If this had an error
    errored: bool,
    /// If the timeout handler has been called at least once
    timeout_handler_called_once: Rc<Cell<bool>>,
}

impl core::fmt::Debug for LuaMutator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LuaMutator")
            .field("name", &self.name)
            .field("func", &self.func)
            .field("mutator", &self.mutator)
            .field(
                "timeout_handler_called_once",
                &self.timeout_handler_called_once,
            )
            .field("eat_errors", &self.eat_errors)
            .field("errored", &self.errored)
            .finish_non_exhaustive()
    }
}

impl LuaMutator {
    /// Creates a new lua mutator, will call the mutator with a random bytes sequence to make sure it's not crashing.
    /// Will error if the mutator hits the instruction limit during validation.
    pub fn new<S: HasRand>(state: &mut S, mutator_lua_fn: &str) -> Result<Self, Error> {
        let lua = Lua::new();
        let func = mutator_lua_fn.to_string();
        let (mutator, timeouted_once) = create_lua_fn(
            &lua,
            state,
            mutator_lua_fn,
            Some(DEFAULT_TIMEOUT_STEPS),
            true,
        )?;
        Ok(Self {
            lua,
            name: Cow::Borrowed("LuaMutator"),
            func,
            mutator,
            timeout_handler_called_once: timeouted_once,
            eat_errors: false,
            errored: false,
        })
    }

    /// Creates a new lua mutator, will call the mutator with a random bytes sequence to make sure it's not crashing.
    /// Runtime errors during subsequent mutations will be converted into [`MutationResult::Skipped`].
    pub fn eat_errors<S: HasRand>(state: &mut S, mutator_lua_fn: &str) -> Result<Self, Error> {
        let mut mutator = Self::new(state, mutator_lua_fn)?;
        mutator.eat_errors = true;
        Ok(mutator)
    }

    /// Sets a custom [`Named::name`] for this [`LuaMutator`].
    #[must_use]
    pub fn with_name(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.name = name.into();
        self
    }

    /// Returns whether this mutator encountered and swallowed a runtime error when `eat_errors` is enabled.
    #[must_use]
    pub fn errored(&self) -> bool {
        self.errored
    }
}

impl<I, S> Mutator<I, S> for LuaMutator
where
    S: HasMetadata + HasRand + HasMaxSize,
    I: HasMutatorBytes + ResizableMutator<u8>,
{
    fn mutate(&mut self, _state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        self.timeout_handler_called_once.set(false);
        let bytes = input.mutator_bytes().to_vec();
        match self.mutator.call::<Vec<u8>>(bytes) {
            Err(err) => {
                if self.eat_errors {
                    log::debug!("Mutation Errored ({err}): {}", self.func);
                    self.errored = true;
                    Ok(MutationResult::Skipped)
                } else {
                    Err(Error::illegal_state(format!("Lua mutation failed: {err}")))
                }
            }
            Ok(mutated) => {
                if mutated == input.mutator_bytes() {
                    Ok(MutationResult::Skipped)
                } else {
                    input.resize(mutated.len(), 0);
                    input.mutator_bytes_mut().copy_from_slice(&mutated);
                    Ok(MutationResult::Mutated)
                }
            }
        }
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for LuaMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "std")]
    use std::println;

    use libafl_bolts::{Error, Named};

    use crate::{
        inputs::BytesInput,
        mutators::{MutationResult, Mutator, lua::LuaMutator},
        state::NopState,
    };

    #[test]
    fn simple_test() {
        let mut state: NopState<BytesInput> = NopState::new();

        let mut lua_mutator = LuaMutator::new(
            &mut state,
            r"function (bytes)
            for i, byte in ipairs(bytes) do
              if math.random() < 0.5 then
                bytes[i] = math.random(0, 255)
              end
            end
            return bytes
          end
              ",
        )
        .unwrap();

        let bytes = vec![0, 1, 2, 3, 4];
        let mut bytesinput = BytesInput::new(bytes);
        for _i in 0..10 {
            let mutation_result = lua_mutator.mutate(&mut state, &mut bytesinput).unwrap();
            if matches!(mutation_result, MutationResult::Mutated) {
                #[cfg(feature = "std")]
                println!("MutationResult: {mutation_result:?} after {_i} iterations");
                return;
            }
        }
        panic!("LuaMutator did not mutate once in 10 tries!");
    }

    #[test]
    fn test_timeout() {
        let mut state: NopState<BytesInput> = NopState::new();
        let res = LuaMutator::new(
            &mut state,
            "function (bytes) local i = 0 while true do i = i + 1 end end",
        );
        assert!(
            matches!(res, Err(Error::IllegalArgument(msg, _)) if msg.contains("Instruction limit")),
            "Expected instruction-limit error!"
        );
    }

    #[test]
    fn test_mutate_timeout_and_eat_errors() {
        let mut state: NopState<BytesInput> = NopState::new();
        let script = r"function (bytes)
            if #bytes == 0 then error('empty') end
            if bytes[1] == 42 then local i = 0 while true do i = i + 1 end end
            bytes[1] = (bytes[1] + 1) % 256
            return bytes
        end";

        let mut strict = LuaMutator::new(&mut state, script).unwrap();
        let mut hang = BytesInput::new(vec![42, 1]);
        assert!(strict.mutate(&mut state, &mut hang).is_err());

        let mut forgiving = LuaMutator::eat_errors(&mut state, script)
            .unwrap()
            .with_name("custom_inc");
        assert_eq!(forgiving.name().as_ref(), "custom_inc");
        let mut ok = BytesInput::new(vec![10, 20]);
        assert_eq!(
            forgiving.mutate(&mut state, &mut ok).unwrap(),
            MutationResult::Mutated
        );
        assert!(!forgiving.errored());

        assert_eq!(
            forgiving.mutate(&mut state, &mut hang).unwrap(),
            MutationResult::Skipped
        );
        assert!(forgiving.errored());
        // VM remains usable after a caught timeout and runtime error while `errored()` stays sticky.
        assert_eq!(
            forgiving
                .mutate(&mut state, &mut BytesInput::new(vec![]))
                .unwrap(),
            MutationResult::Skipped
        );
        assert_eq!(
            forgiving.mutate(&mut state, &mut ok).unwrap(),
            MutationResult::Mutated
        );
        assert!(forgiving.errored());
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_load_lua_mutations_filters_sorts_and_names() {
        use std::{fs, path::PathBuf};

        use crate::{inputs::HasMutatorBytes, mutators::lua::load_lua_mutations};

        struct TempDirGuard(PathBuf);
        impl Drop for TempDirGuard {
            fn drop(&mut self) {
                if let Err(err) = fs::remove_dir_all(&self.0) {
                    log::debug!("Failed to clean temp dir {}: {err}", self.0.display());
                }
            }
        }

        let dir = std::env::temp_dir().join(format!("libafl_lua_test_{}", std::process::id()));
        let guard = TempDirGuard(dir);
        fs::create_dir_all(guard.0.join("nested.lua")).unwrap();
        fs::write(guard.0.join("README.md"), "ignored").unwrap();
        fs::write(guard.0.join("c_bad.lua"), "not valid lua").unwrap();
        fs::write(
            guard.0.join("b_second.LUA"),
            "return function(b) b[1] = 2 return b end",
        )
        .unwrap();
        fs::write(
            guard.0.join("a_first.lua"),
            "return function(b) b[1] = 1 return b end",
        )
        .unwrap();

        let mut mutators =
            load_lua_mutations::<BytesInput, NopState<BytesInput>>(&guard.0).unwrap();
        assert_eq!(mutators.len(), 2);
        assert_eq!(mutators[0].name().as_ref(), "LuaMutator:a_first");
        assert_eq!(mutators[1].name().as_ref(), "LuaMutator:b_second");

        let mut state: NopState<BytesInput> = NopState::new();
        let mut input = BytesInput::new(vec![9, 9]);
        assert_eq!(
            mutators[0].mutate(&mut state, &mut input).unwrap(),
            MutationResult::Mutated
        );
        assert_eq!(input.mutator_bytes(), &[1, 9]);
    }
}
