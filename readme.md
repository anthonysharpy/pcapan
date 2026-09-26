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
- The TCP byte stream is output as text. Obviously this comes with its own set of issues, but I figured it was more interesting to look at than a big list of numbers or hex values.
- I've not added support for decoding the byte stream protocol. It *seems* it's just a length header of 5 characters and then the data after that. It seemed pretty simple in comparison to everything else I've done for this project so I didn't think there'd be much added value in including it.
- The program is not really designed to be fast and has not been optimised at all.
- It was sort-of impossible to create the protocol type histogram because the test data only includes TCP packets. But we do output the number of TCP packets found.

## Known Bugs

This is just a coding exercise so there's lots of incorrect assumptions and buggy behaviour. Some of the most serious bugs include:

- The packets are processed in the order they come in the file (i.e. usually timestamp order). This just so happens to produce correctly ordered byte-streams on the given test data, but in the real world TCP packet ordering is dictated by the sequence number. To be fair though, the intention was to show the "conversation" between the two devices, and because both devices in TCP use different sequence numbers, the only way to do that is via timestamps. So I'm not even sure I would call this a bug.
- The code assumes the system it is running on is always little-endian. This program will not work on big-endian machines. To be fair though, big-endian systems are rare.
- For simplicity the maximum number of connections and the number of packets within those connections that the program supports is hard-limited.
- We don't track when connections finish or reset so theoretically different connections can get treated as the same connection if their ports and IPs match.
- Corrupt/incomplete data is not always handled as gracefully as it could be, although there are checks to prevent crashes etc.
- No support for anything other than TCP.
- Because the byte stream is interpreted as text and output to the console, it sometimes corrupts the console output very slightly.
- `analyse_bandwidth` will produce garbage output in some extreme scenarios (e.g. data contains no packets).

## Compiling

Do `make` in the root directory.

## Running

Do `make run` or run the executable manually.
