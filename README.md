# nmap
                         MAIN THREAD

      PCAP
        │
        ▼
   L2 locator
        │
   ┌────┴────┐
 IPv4       IPv6
 parser     parser + extension headers
   │           │
   └─────┬─────┘
         ▼
   t_nmap_reply
         │
         ▼
      MATCH
         │
         ▼
     CLASSIFY
         │
         ▼
      RESULT


                    RUNTIME

 PENDING ──► QUEUED ──► OUTSTANDING
    ▲                       │
    │                       ├── response ──► DONE
    │                       │
    └──── retry ◄── timeout ┘
                            │
                            └── retry policy exhausted
                                      │
                                      ▼
                                     DONE


                    SENDER THREADS

            shared sender queue
              /     |      \
             /      |       \
        worker 0 worker 1 ... worker N

 Workers:
   - do not read PCAP
   - do not classify
   - do not expire
   - do not schedule
   - only transition QUEUED -> OUTSTANDING + send()