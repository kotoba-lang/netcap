# kotoba-lang/netcap

Portable CLJC networking capability contracts for kotoba runtimes.

`netcap` models TCP, UDP, and DNS access as WIT-style capability tokens. It
does not open sockets directly; hosts inject concrete networking drivers and
the manager gates calls through policy.

## Test

```bash
clojure -M:test
```
