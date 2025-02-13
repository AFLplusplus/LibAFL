# Migrating from <0.12 to 0.12

We deleted `TimeoutExecutor` and `TimeoutForkserverExecutor` and make it mandatory for `InProcessExecutor` and `ForkserverExecutor` to have the timeout. Now `InProcessExecutor` and `ForkserverExecutor` have the default timeout of 5 seconds.

## Reason for This Change.
In 99% of the case, it is advised to have the timeout for the fuzzer. This is because we do not want the fuzzer to stop forever just because the target has hit a path that resulted in a infinite-loop.

## What changed
You do not have to wrap the executor with `TimeoutExecutor` anymore. You can just use `InProcessExecutor::new()` to instantiate the executor with the default timeout or use `InProcessExecutor::timeout(duration)` to start the executor with the customized duration of timeout.