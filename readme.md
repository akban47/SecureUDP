# Security Protocol Implementation

## Design Choices

1. Implemented a MessageBlock structure with data-first layout to optimize memory access patterns and improve readability. Used unions and bitfields for efficient memory management and status tracking.

2. Each protocol state is handled distinctly with specific message building and parsing approaches:

## Implementation Challenges

1. Encryption and MAC Integration: Due to time constraints and implementation complexity, I was unable to fully implement:
   - Client-side encryption/MAC functionality 
   - Server-side encryption/MAC functionality 
   These components would have required:
   - Proper key derivation from the handshake
   - Correct implementation of encrypt_data function
   - Handling of malformed authentication codes

2. For the implemented parts:
   - Used unions and component flags for structured message handling
   - Implemented robust error checking and state transitions
   - Ensured proper certificate and signature verification
   - Maintained secure nonce handling throughout the protocol