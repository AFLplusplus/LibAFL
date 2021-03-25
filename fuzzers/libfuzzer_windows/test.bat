mkdir crashes
del .\.libfuzzer_test.elf

cargo build --example libfuzzer_windows --release
timeout /T 1
cp ..\..\target\release\examples\libfuzzer_windows.exe .\.libfuzzer_test.exe
timeout /T 1

# The broker
start .\.libfuzzer_test.exe
# Give the broker time to spawn
timeout /T 1
echo "Spawning client"
start .\.libfuzzer_test.exe
# .\.libfuzzer_test.exe > nul

timeout /T 10
echo "Finished fuzzing for a bit"
TASKKILL /IM .libfuzzer_test.exe
del .libfuzzer_test.exe
