## Prerequisites

- This C program uses C23 and is compiled using GCC 15 on Linux. With some modifications to the makefile, this program will compile on older versions of GCC, but it's probably best if you just update to GCC 15 if you haven't already:

```
gcc -v # Check version
```

```
sudo apt install gcc-15
```

The GCC version can be changed in the makefile if you don't want to use GCC 15 (`GCCVERSION` variable).

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
- Due to time constraints I've not included any tests. If that's something of interest then see my other project at https://github.com/anthonysharpy/nanofill.
- The TCP byte stream is output as text. Obviously this comes with its own set of issues, but is probably a bit nicer to look at than a big list of numbers.
- I've not added support for decoding the byte stream protocol. It seems it's just a length header of 5 characters and then the data after that. It's pretty simple so I didn't think there'd be much added value in including it.
- Due to time constraints I haven't added support for measuring performance/bandwidth. A good example of this also be https://github.com/anthonysharpy/nanofill.
- The program is not designed to be fast or optimised at all.
- When we parse a packet, we create a copy of all its data. Obviously the downside is that this is much slower. However from a design perspective it's more friendly because otherwise, if the original data gets freed, and we try and interpret a packet that was derived from it, that's a pretty nasty bug.

## Known Bugs

This is just a coding exercise so there's lots of incorrect assumptions and buggy behaviour. Some of the most serious bugs include:

- The packets are ordered by their timestamp. This just so happens to produce correctly ordered byte-streams on the given test data, but in the real world TCP packet ordering is dictated by the sequence number.
- The code assumes the system it is running on will always be little-endian. Big-endian systems are rare, but this program will not work on them.
- Due to laziness, the maximum number of connections and the number of packets within those connections that the program supports is hard-limited.

## Compiling

Do `make` in the root directory.

## Running

Do `make run` or run the executable manually.
