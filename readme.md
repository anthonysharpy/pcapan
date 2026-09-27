## Prerequisites

This C program uses C23 and is compiled using GCC 13 on Linux. With some modifications to the makefile, this program might compile on older versions of GCC (the GCC version can be changed in the makefile [`GCCVERSION` variable]).

## Original Task

```
Write a small utility in C to analyze the raw network traffic in the attached pcap file (http://en.wikipedia.org/wiki/Pcap).

Please send back the complete source code you wrote. It should be able to compile and run locally.

Some suggested ideas:
- Protocol histogram (number of TCP packets/other protocol)
- Calculate bandwidth/performance metrics
- Extract TCP byte stream
- Decode the TCP byte stream protocol
```

## Things to Note

- The source code uses C23, which has a slightly more modern feature set.
- The code was not designed to handle every possible edge case. While it was written with best-practices in mind, it wasn't validated against anything other than the provided example data. It goes without saying that a lot of functionality might be broken or completely missing with another data set.
- The input file is hard-coded.
- Due to time constraints I've not included any tests. If that's something of interest then I would definitely recommend my other project at https://github.com/anthonysharpy/nanofill.
- I've not added support for decoding the byte stream protocol. It *seems* it's just a length header of 5 characters and then the data after that. It seemed relatively simple in comparison to everything else I've done for this project so I didn't think there'd be loads of added value in including it.
- It was sort-of impossible to create the protocol type histogram because the test data only includes TCP packets. But we do output the number of TCP packets found.
- When we parse the TCP packets, we also allocate IPV4 and Ethernet packets on the heap and then immediately free them. This might seem pointless, but this is done with forward compatibility in mind. Currently we parse a whole bunch of TCP packets which are allocated on the heap (because if we have millions of packets then they will not fit on the stack). In the same way, we allocate the other packets like this too. The reason is because one day we might have a need to generate millions of IPV4 or Ethernet packets etc. Obviously this program was not actually designed to support that, but I've kept it like this since it's what made the most sense to me in terms of design. And obviously we could have one version of the function that allocated on the heap, and another that merely used the stack, but I thought that that was over-engineering it for this simple project. And besides, it was a good opportunity to show memory-mangement skills.

## Known Bugs

This is just a coding exercise so there's lots of incorrect assumptions and buggy behaviour. Some of the most serious bugs include:

- The packets are processed in the order they come in the file (i.e. usually timestamp order). This just so happens to produce correctly ordered byte-streams on the given test data, but in the real world TCP packet ordering is dictated by the sequence number. To be fair though, my intention was to show the "conversation" between the two devices (regardless of order of processing), and the only way to do that is via timestamps. So I'm not even sure I would call this a bug. A fully reconstructed byte stream would be sorted using sequence and acknowledgment numbers.
- For simplicity the maximum number of connections and the number of packets within those connections that the program supports is hard-limited.
- We don't track when connections finish or reset so theoretically different connections can get treated as the same connection if their ports and IPs match.
- Corrupt/incomplete data is not always handled as gracefully as it could be, although there are checks to prevent crashes etc.
- No support for anything other than TCP.

## Compiling

Do `make` in the root directory.

## Running

Do `make run` or run the executable manually.
