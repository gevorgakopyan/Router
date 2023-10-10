# Simple Router

In this project, I wrote a simple router equipped with a static routing table. This router successfully processes raw Ethernet frames, akin to a real router, forwarding them to the appropriate outgoing interface and crafting new frames as needed. While the provided starter code supplied the framework to receive Ethernet frames, I developed the intricate forwarding logic.

I leveraged high-level abstractions, including C++11 extensions, for aspects not directly tied to networking, such as string parsing and multi-threading.