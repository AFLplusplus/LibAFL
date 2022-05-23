from pylibafl.libafl import *
import ctypes

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
        (self.h)(input)
        ExitKind.ok()

libc = ctypes.cdll.LoadLibrary("libc.so.6")

area_ptr = libc.calloc(1, 4096)

observer = StdMapObserverI8("mymap", area_ptr, 4096)

m = observer.as_map_observer()

observers = ObserversTuple([observer.as_map_observer().as_observer()])

feedback = MaxMapFeedbackI8(m)

objective = CrashFeedback()

fuzzer = StdFuzzer(feedback.as_feedback(), objective.as_feedback())

rand = StdRand.with_current_nanos()

state = StdState(rand.as_rand(), InMemoryCorpus().as_corpus(), InMemoryCorpus().as_corpus(), feedback.as_feedback(), objective.as_feedback())

monitor = SimpleMonitor(lambda s: print(s))

mgr = SimpleEventManager(monitor.as_monitor())

def harness(buf):
    #print(buf)
    m[0] = 1
    if len(buf) > 0 and buf[0] == 66:
        m[1] = 1

executor = InProcessExecutor(harness, observers, fuzzer, state, mgr.as_manager())

stage = StdMutationalStage(StdHavocMutator().as_mutator())

stage_tuple_list = StagesTuple([stage.as_stage()])

fuzzer.add_input(state, executor.as_executor(), mgr.as_manager(), b'\0\0')

fuzzer.fuzz_loop(executor.as_executor(), state, mgr.as_manager(), stage_tuple_list)
