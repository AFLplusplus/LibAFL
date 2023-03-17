from pylibafl.libafl import *
import ctypes
import platform

MAP_SIZE = 4096


class FooObserver(BaseObserver):
    def __init__(self):
        self.n = 0

    def name(self):
        return "Foo"

    def pre_exec(self, state, input):
        if self.n % 10000 == 0:
            print("FOO!", self.n, input)
        self.n += 1


class FooFeedback(BaseFeedback):
    def is_interesting(self, state, mgr, input, observers, exit_kind):
        ob = observers.match_name("Foo").unwrap_py()
        return ob.n % 10000 == 0


class FooExecutor(BaseExecutor):
    def __init__(self, harness, observers: ObserversTuple):
        self.h = harness
        self.o = observers

    def observers(self):
        return self.o

    def run_target(self, fuzzer, state, mgr, input) -> ExitKind:
        return (self.h)(input)


if platform.system() == "Darwin":
    libc = ctypes.cdll.LoadLibrary("libc.dylib")
else:
    libc = ctypes.cdll.LoadLibrary("libc.so.6")

# Get a buffer to use for our map observer
libc.calloc.restype = ctypes.c_void_p
area_ptr = libc.calloc(1, MAP_SIZE)

observer = StdMapObserverI8("mymap", area_ptr, MAP_SIZE)

m = observer.as_map_observer()

observers = ObserversTuple(
    [observer.as_map_observer().as_observer(), FooObserver().as_observer()]
)

feedback = feedback_or(MaxMapFeedbackI8(m).as_feedback(), FooFeedback().as_feedback())

objective = feedback_and_fast(
    CrashFeedback().as_feedback(), MaxMapFeedbackI8(m).as_feedback()
)

fuzzer = StdFuzzer(feedback, objective)

rand = StdRand.with_current_nanos()

state = StdState(
    rand.as_rand(),
    InMemoryCorpus().as_corpus(),
    InMemoryCorpus().as_corpus(),
    feedback,
    objective,
)

monitor = SimpleMonitor(lambda s: print(s))

mgr = SimpleEventManager(monitor.as_monitor())


def harness(buf) -> ExitKind:
    """
    The harness fn that the fuzzer will execute in a loop
    """
    # print(buf)

    # set the observer map byte from python
    m[0] = 1
    if len(buf) > 0 and buf[0] == ord("a"):
        m[1] = 1
        if len(buf) > 1 and buf[1] == ord("b"):
            m[2] = 1
            if len(buf) > 2 and buf[2] == ord("c"):
                m[3] = 1
                return ExitKind.crash()
    return ExitKind.ok()


# executor = InProcessExecutor(harness, observers, fuzzer, state, mgr.as_manager())

executor = FooExecutor(harness, observers)

stage = StdMutationalStage(StdHavocMutator().as_mutator())

stage_tuple_list = StagesTuple([stage.as_stage()])

fuzzer.add_input(state, executor.as_executor(), mgr.as_manager(), b"\0\0")

print("Starting to fuzz from python!")

fuzzer.fuzz_loop(executor.as_executor(), state, mgr.as_manager(), stage_tuple_list)
