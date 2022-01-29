from pylibafl import libafl

# LIBRARY WRAPPER

def map_observer_wrapper(map_observer):
    if type(map_observer).__name__ == "OwnedMapObserverI32":
        return libafl.MapObserverI32.new_from_owned(map_observer)

def executor_wrapper(executor):
    if type(executor).__name__ == "OwnedInProcessExecutorI32":
        return libafl.ExecutorI32.new_from_inprocess(executor)

def monitor_wrapper(monitor):
    if type(monitor).__name__ == "SimpleMonitor":
        return libafl.Monitor.new_from_simple(monitor)

def event_manager_wrapper(event_manager):
    if type(event_manager).__name__ == "SimpleEventManager":
        return libafl.EventManager.new_from_simple(event_manager)

def corpus_wrapper(corpus):
    if type(corpus).__name__ == "InMemoryCorpus":
        return libafl.Corpus.new_from_in_memory(corpus)
    if type(corpus).__name__ == "OnDiskCorpus":
        return libafl.Corpus.new_from_on_disk(corpus)

def rand_wrapper(rand):
    if type(rand).__name__ == "StdRand":
        return libafl.Rand.new_from_std(rand)

# CODE WRITTEN BY USER

def harness(inp):
    if len(inp.hex()) >= 2 and inp.hex()[:2] == '61':
        raise Exception("NOOOOOO =)")

map_observer = libafl.OwnedMapObserverI32("signals", [0] * 16)

feedback_state = libafl.MapFeedbackStateI32.with_observer(map_observer_wrapper(map_observer))

feedback = libafl.MaxMapFeedbackI32(feedback_state, map_observer_wrapper(map_observer))

state = libafl.StdStateI32(
    rand_wrapper(libafl.StdRand.with_current_nanos()), 
    corpus_wrapper(libafl.InMemoryCorpus()), 
    corpus_wrapper(libafl.OnDiskCorpus("./crashes")), 
    feedback_state
)

monitor = libafl.SimpleMonitor()

mgr = libafl.SimpleEventManager(monitor_wrapper(monitor))

fuzzer = libafl.StdFuzzerI32(feedback)

executor = libafl.OwnedInProcessExecutorI32(harness, map_observer_wrapper(map_observer), fuzzer, state, event_manager_wrapper(mgr))

generator = libafl.RandPrintablesGenerator(32)

state.generate_initial_inputs(fuzzer, executor_wrapper(executor), generator, event_manager_wrapper(mgr), 8000000)