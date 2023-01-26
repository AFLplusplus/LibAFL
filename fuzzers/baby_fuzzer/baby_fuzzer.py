from pylibafl import libafl

# LIBRARY WRAPPER

def map_observer_wrapper(map_observer):
    if type(map_observer).__name__ == "OwnedMapObserverI32":
        return libafl.MapObserverI32.new_owned(map_observer)

def executor_wrapper(executor):
    if type(executor).__name__ == "OwnedInProcessExecutorI32":
        return libafl.ExecutorI32.new_from_inprocess(executor)

def monitor_wrapper(monitor):
    return monitor.as_monitor()

def event_manager_wrapper(event_manager):
    return event_manager.as_manager()

def corpus_wrapper(corpus):
    if type(corpus).__name__ == "InMemoryCorpus":
        return libafl.Corpus.new_in_memory(corpus)
    if type(corpus).__name__ == "OnDiskCorpus":
        return libafl.Corpus.new_on_disk(corpus)

def rand_wrapper(rand):
    if type(rand).__name__ == "StdRand":
        return libafl.Rand.new_std(rand)

def stage_wrapper(stage):
    if type(stage).__name__ == "StdScheduledHavocMutationsStageI32":
        return libafl.StageI32.new_from_std_scheduled(stage)

# CODE WRITTEN BY USER

def harness(inp):
    if len(inp.hex()) >= 2 and inp.hex()[:2] == '61':
        raise Exception("NOOOOOO =)")

map_observer = libafl.OwnedMapObserverI32("signals", [0] * 16)

feedback = libafl.MaxMapFeedbackI32(map_observer_wrapper(map_observer))
objective = libafl.CrashFeedback()

state = libafl.StdState(
    rand_wrapper(libafl.StdRand.with_current_nanos()), 
    corpus_wrapper(libafl.InMemoryCorpus()), 
    corpus_wrapper(libafl.OnDiskCorpus("./crashes")), 
    feedback.as_feedback(),
    objective.as_feedback(),
)

monitor = libafl.SimpleMonitor(lambda x: print(x))

mgr = libafl.SimpleEventManager(monitor_wrapper(monitor))

fuzzer = libafl.StdFuzzer(feedback.as_feedback(), objective.as_feedback())

executor = libafl.InProcessExecutor(harness, map_observer_wrapper(map_observer), fuzzer, state, event_manager_wrapper(mgr))

generator = libafl.RandPrintablesGeneratorI32(32)

state.generate_initial_inputs(fuzzer, executor_wrapper(executor), generator, event_manager_wrapper(mgr), 8)

stage = libafl.StdScheduledHavocMutationsStageI32.new_from_scheduled_havoc_mutations()

stage_tuple_list = libafl.StagesOwnedListI32(stage_wrapper(stage))

fuzzer.fuzz_loop(executor_wrapper(executor), state, event_manager_wrapper(mgr), stage_tuple_list)