How to perf:

```
perf record -e task-clock ./PROGRAM

perf report --stdio --dsos=PROGRAM

rm perf.data
```
