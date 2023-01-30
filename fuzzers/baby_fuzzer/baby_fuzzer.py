from pylibafl import libafl

# LIBRARY WRAPPER

def map_observer_wrapper(map_observer):
    if type(map_observer).__name__ == "OwnedMapObserverI32":
        return libafl.MapObserverI32.new_owned(map_observer)

def executor_wrapper(executor):
    if type(executor).__name__ == "InProcessExecutor":
        return libafl.Executor.new_inprocess(executor)

def generator_wrapper(generator):
    if type(generator).__name__ == "RandPrintablesGenerator":
        return libafl.Generator.new_rand_printables(generator)

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

def mutator_wrapper(mutator):
    if type(mutator).__name__ == "StdHavocMutator":
        return libafl.Mutator.new_std_havoc(mutator)

def stage_wrapper(stage):
    if type(stage).__name__ == "StdMutationalStage":
        return libafl.Stage.new_std_mutational(stage)

# CODE WRITTEN BY USER

map_observer = libafl.OwnedMapObserverI32("signals", [0] * 16)

def harness(inp):
    #print(inp)
    map_observer[0] = 1
    if len(inp) > 0 and inp[0] == ord('a'):
        map_observer[1] = 1
        if len(inp) > 1 and inp[1] == ord('b'):
            map_observer[2] = 1
            if len(inp) > 2 and inp[2] == ord('c'):
                map_observer[3] = 1
                raise Exception("NOOOOOO =)")

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

observers = libafl.ObserversTuple([libafl.Observer.new_map_i32(map_observer_wrapper(map_observer))])

executor = libafl.InProcessExecutor(harness, observers, fuzzer, state, event_manager_wrapper(mgr))

generator = libafl.RandPrintablesGenerator(32)

state.generate_initial_inputs(fuzzer, executor_wrapper(executor), generator_wrapper(generator), event_manager_wrapper(mgr), 3)

mutator = libafl.StdHavocMutator()

stage = libafl.StdMutationalStage(mutator_wrapper(mutator))

stages = libafl.StagesTuple([stage_wrapper(stage)])

fuzzer.fuzz_loop(executor_wrapper(executor), state, event_manager_wrapper(mgr), stages)
